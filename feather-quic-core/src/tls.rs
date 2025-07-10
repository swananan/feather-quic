use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::hkdf::{Prk, Salt, HKDF_SHA256, HKDF_SHA384};
use ring::rand::SystemRandom;
use ring::{digest, hmac};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, Write};
use tracing::{info, trace, warn};

use crate::config::QuicConfig;
use crate::connection::{QuicLevel, QUIC_STATELESS_RESET_TOKEN_SIZE};
use crate::crypto::{hkdf_expand, QUIC_SHA256_SECRET_LENGTH, QUIC_SHA384_SECRET_LENGTH};
use crate::error_code::TlsError;
use crate::frame::QuicFrameType;
use crate::transport_parameters::{
    create_client_transport_parameters, parse_server_transport_parameters,
    search_transport_parameters, PreferredAddress, TransportParameter,
};
use crate::utils::{remaining_bytes, write_cursor_bytes_with_pos};

// Algorithm used in QUIC initial phase
pub(crate) const TLS_AES_128_GCM_SHA256: u16 = 0x1301;

pub(crate) const TLS_AES_256_GCM_SHA384: u16 = 0x1302;

const TLS_LENGTH_FIELD_SIZE: usize = 3;
const TLS_EXTS_LENGTH_FIELD_SIZE: usize = 2;
const TLS_QUIC_EXT_LENGTH_FIELD_SIZE: usize = 2;
const TLS_HANDSHAKE_RANDOM_SIZE: usize = 32;
const TLS_FINISHED_LENGTH: u16 = 32;

const TLS_12_VERSION: u16 = 0x0303;
const TLS_13_VERSION: u16 = 0x0304;
const TLS_ECDH_X25519: u16 = 0x001d;

const TLS_DERIVED_SECRET_LABEL: &[u8] = b"tls13 derived";
const TLS_CLIENT_HANDSHAKE_SECRET_LABEL: &[u8] = b"tls13 c hs traffic";
const TLS_SERVER_HANDSHAKE_SECRET_LABEL: &[u8] = b"tls13 s hs traffic";
const TLS_CLIENT_APPLICATION_SECRET_LABEL: &[u8] = b"tls13 c ap traffic";
const TLS_SERVER_APPLICATION_SECRET_LABEL: &[u8] = b"tls13 s ap traffic";
const TLS_FINISHED_SECRET_LABEL: &[u8] = b"tls13 finished";

// https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
const TLS_CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
const TLS_SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
const TLS_CLIENT_TRAFFIC_SECRET_0: &str = "CLIENT_TRAFFIC_SECRET_0";
const TLS_SERVER_TRAFFIC_SECRET_0: &str = "SERVER_TRAFFIC_SECRET_0";
const TLS_CLIENT_TRAFFIC_SECRET: &str = "CLIENT_TRAFFIC_SECRET_";
const TLS_SERVER_TRAFFIC_SECRET: &str = "SERVER_TRAFFIC_SECRET_";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl HandshakeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            4 => Some(HandshakeType::NewSessionTicket),
            5 => Some(HandshakeType::EndOfEarlyData),
            8 => Some(HandshakeType::EncryptedExtensions),
            11 => Some(HandshakeType::Certificate),
            13 => Some(HandshakeType::CertificateRequest),
            15 => Some(HandshakeType::CertificateVerify),
            20 => Some(HandshakeType::Finished),
            24 => Some(HandshakeType::KeyUpdate),
            254 => Some(HandshakeType::MessageHash),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtensionType {
    ServerName = 0,                           // RFC 6066
    MaxFragmentLength = 1,                    // RFC 6066
    StatusRequest = 5,                        // RFC 6066
    SupportedGroups = 10,                     // RFC 8422, 7919
    SignatureAlgorithms = 13,                 // RFC 8446
    UseSrtp = 14,                             // RFC 5764
    Heartbeat = 15,                           // RFC 6520
    ApplicationLayerProtocolNegotiation = 16, // RFC 7301
    SignedCertificateTimestamp = 18,          // RFC 6962
    ClientCertificateType = 19,               // RFC 7250
    ServerCertificateType = 20,               // RFC 7250
    Padding = 21,                             // RFC 7685
    PreSharedKey = 41,                        // RFC 8446
    EarlyData = 42,                           // RFC 8446
    SupportedVersions = 43,                   // RFC 8446
    Cookie = 44,                              // RFC 8446
    PskKeyExchangeModes = 45,                 // RFC 8446
    CertificateAuthorities = 47,              // RFC 8446
    OidFilters = 48,                          // RFC 8446
    PostHandshakeAuth = 49,                   // RFC 8446
    SignatureAlgorithmsCert = 50,             // RFC 8446
    KeyShare = 51,                            // RFC 8446
    QuicTransportParameters = 57, // https://www.rfc-editor.org/rfc/rfc9001.html#section-8.2
    Unknown(u16),
}

impl ExtensionType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => ExtensionType::ServerName,
            1 => ExtensionType::MaxFragmentLength,
            5 => ExtensionType::StatusRequest,
            10 => ExtensionType::SupportedGroups,
            13 => ExtensionType::SignatureAlgorithms,
            14 => ExtensionType::UseSrtp,
            15 => ExtensionType::Heartbeat,
            16 => ExtensionType::ApplicationLayerProtocolNegotiation,
            18 => ExtensionType::SignedCertificateTimestamp,
            19 => ExtensionType::ClientCertificateType,
            20 => ExtensionType::ServerCertificateType,
            21 => ExtensionType::Padding,
            41 => ExtensionType::PreSharedKey,
            42 => ExtensionType::EarlyData,
            43 => ExtensionType::SupportedVersions,
            44 => ExtensionType::Cookie,
            45 => ExtensionType::PskKeyExchangeModes,
            47 => ExtensionType::CertificateAuthorities,
            48 => ExtensionType::OidFilters,
            49 => ExtensionType::PostHandshakeAuth,
            50 => ExtensionType::SignatureAlgorithmsCert,
            51 => ExtensionType::KeyShare,
            57 => ExtensionType::QuicTransportParameters,
            _ => ExtensionType::Unknown(value),
        }
    }

    pub fn as_u16(self) -> u16 {
        match self {
            ExtensionType::ServerName => 0,
            ExtensionType::MaxFragmentLength => 1,
            ExtensionType::StatusRequest => 5,
            ExtensionType::SupportedGroups => 10,
            ExtensionType::SignatureAlgorithms => 13,
            ExtensionType::UseSrtp => 14,
            ExtensionType::Heartbeat => 15,
            ExtensionType::ApplicationLayerProtocolNegotiation => 16,
            ExtensionType::SignedCertificateTimestamp => 18,
            ExtensionType::ClientCertificateType => 19,
            ExtensionType::ServerCertificateType => 20,
            ExtensionType::Padding => 21,
            ExtensionType::PreSharedKey => 41,
            ExtensionType::EarlyData => 42,
            ExtensionType::SupportedVersions => 43,
            ExtensionType::Cookie => 44,
            ExtensionType::PskKeyExchangeModes => 45,
            ExtensionType::CertificateAuthorities => 47,
            ExtensionType::OidFilters => 48,
            ExtensionType::PostHandshakeAuth => 49,
            ExtensionType::SignatureAlgorithmsCert => 50,
            ExtensionType::KeyShare => 51,
            ExtensionType::QuicTransportParameters => 57,
            ExtensionType::Unknown(value) => value,
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc8446#appendix-A.1
#[derive(Debug, PartialEq, Eq)]
enum TlsClientState {
    Uninitialized,
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
}

#[derive(Debug, Clone, Default)]
struct TlsConfig {
    server_name: String,
    alpn: String,
}

impl TlsConfig {
    pub fn new(server_name: String, alpn: String) -> Self {
        Self { server_name, alpn }
    }
}

#[allow(dead_code)]
pub(crate) struct TlsContext {
    tls_config: TlsConfig,
    state: TlsClientState,
    selected_chipher_suite: Option<u16>,
    private_key: Option<EphemeralPrivateKey>,
    c_tp: Vec<TransportParameter>,
    s_tp: Option<Vec<TransportParameter>>,

    ap_context: Option<digest::Context>,
    client_hello_message: Option<Vec<u8>>,
    client_hello_random: Option<[u8; TLS_HANDSHAKE_RANDOM_SIZE]>,

    send_queue: VecDeque<(Vec<u8>, QuicLevel)>,
    recv_buf_store: Vec<u8>,

    ssl_key_file: Option<File>,
    handshake_server_secret: Option<Vec<u8>>,
    handshake_client_secret: Option<Vec<u8>>,
    ssl_key_update_times: u32,

    // for application keys-derive
    handshake_secret: Option<Vec<u8>>,

    application_server_secret: Option<Vec<u8>>,
    application_client_secret: Option<Vec<u8>>,
}

trait FromTransportParam {
    fn from_param(param: &TransportParameter) -> Self;
}

impl FromTransportParam for u64 {
    fn from_param(param: &TransportParameter) -> Self {
        match param {
            TransportParameter::MaxIdleTimeout(v) => *v,
            TransportParameter::MaxAckDelay(v) => (*v).into(),
            TransportParameter::AckDelayExponent(v) => (*v).into(),
            TransportParameter::InitialMaxData(v) => *v,
            TransportParameter::InitialMaxStreamDataBidiLocal(v) => *v,
            TransportParameter::InitialMaxStreamDataBidiRemote(v) => *v,
            TransportParameter::InitialMaxStreamDataUni(v) => *v,
            TransportParameter::InitialMaxStreamsBidi(v) => *v,
            TransportParameter::InitialMaxStreamsUni(v) => *v,
            _ => panic!("Unexpected transport parameter type"),
        }
    }
}

impl FromTransportParam for u16 {
    fn from_param(param: &TransportParameter) -> Self {
        match param {
            TransportParameter::MaxAckDelay(v) => *v,
            TransportParameter::MaxUdpPayloadSize(v) => *v,
            _ => panic!("Unexpected transport parameter type"),
        }
    }
}

impl FromTransportParam for u8 {
    fn from_param(param: &TransportParameter) -> Self {
        match param {
            TransportParameter::AckDelayExponent(v) => *v,
            TransportParameter::ActiveConnectionIdLimit(v) => *v,
            _ => panic!("Unexpected transport parameter type"),
        }
    }
}

impl FromTransportParam for [u8; QUIC_STATELESS_RESET_TOKEN_SIZE as usize] {
    fn from_param(param: &TransportParameter) -> Self {
        match param {
            TransportParameter::StatelessResetToken(v) => *v,
            _ => panic!("Unexpected transport parameter type"),
        }
    }
}

impl FromTransportParam for bool {
    fn from_param(param: &TransportParameter) -> Self {
        match param {
            TransportParameter::DisableActiveMigration(v) => *v,
            _ => panic!("Unexpected transport parameter type"),
        }
    }
}

impl FromTransportParam for PreferredAddress {
    fn from_param(param: &TransportParameter) -> Self {
        match param {
            TransportParameter::PreferredAddress(v) => v.clone(),
            _ => panic!("Unexpected transport parameter type"),
        }
    }
}

impl FromTransportParam for Vec<u8> {
    fn from_param(param: &TransportParameter) -> Self {
        match param {
            TransportParameter::OriginalDestinationConnectionId(id) => id.clone(),
            TransportParameter::InitialSourceConnectionId(id) => id.clone(),
            TransportParameter::RetrySourceConnectionId(id) => id.clone(),
            _ => panic!("Unexpected transport parameter type for Vec<u8>"),
        }
    }
}

impl TlsContext {
    #[allow(unused_variables)]
    pub(crate) fn new(quic_config: &QuicConfig, scid: &[u8]) -> Self {
        let file = if let Some(ref file_path) = quic_config.get_key_log_file() {
            info!("SSLKEYLOG path is {}", file_path);
            match OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(file_path)
            {
                Err(e) => {
                    warn!("Failed to open SSLKEYLOG file {file_path}: {e}");
                    None
                }
                Ok(f) => Some(f),
            }
        } else {
            None
        };

        Self {
            state: TlsClientState::Uninitialized,
            selected_chipher_suite: None,
            tls_config: TlsConfig::new(quic_config.get_server_name(), quic_config.get_alpn()),

            ap_context: None,
            client_hello_message: None,
            client_hello_random: None,

            ssl_key_update_times: 1,
            ssl_key_file: file,
            handshake_server_secret: None,
            handshake_client_secret: None,
            handshake_secret: None,
            application_server_secret: None,
            application_client_secret: None,
            private_key: None,
            recv_buf_store: vec![],
            send_queue: VecDeque::new(),
            s_tp: None,
            c_tp: create_client_transport_parameters(quic_config, scid),
        }
    }

    pub(crate) fn start_tls_handshake(&mut self) -> Result<()> {
        self.state = TlsClientState::Uninitialized;
        let client_hello = self.create_client_hello_message()?;
        self.send_queue
            .push_back((client_hello, QuicLevel::Initial));
        Ok(())
    }

    pub(crate) fn should_derive_hs_secret(&self) -> bool {
        self.state == TlsClientState::WaitEncryptedExtensions
    }

    pub(crate) fn should_derive_ap_secret(&self) -> bool {
        self.state == TlsClientState::Connected
    }

    pub(crate) fn have_server_transport_params(&self) -> bool {
        self.s_tp.is_some()
    }

    pub(crate) fn get_handshake_client_secret(&self) -> Result<&Vec<u8>> {
        self.handshake_client_secret
            .as_ref()
            .ok_or_else(|| anyhow!("Handshake client secret not available"))
    }

    pub(crate) fn get_handshake_server_secret(&self) -> Result<&Vec<u8>> {
        self.handshake_server_secret
            .as_ref()
            .ok_or_else(|| anyhow!("Handshake server secret not available"))
    }

    pub(crate) fn get_application_client_secret(&self) -> Result<&Vec<u8>> {
        self.application_client_secret
            .as_ref()
            .ok_or_else(|| anyhow!("Application client secret not available"))
    }

    pub(crate) fn get_application_server_secret(&self) -> Result<&Vec<u8>> {
        self.application_server_secret
            .as_ref()
            .ok_or_else(|| anyhow!("Application server secret not available"))
    }

    fn get_peer_transport_param<T, F>(&self, predicate: F) -> Option<T>
    where
        F: Fn(&TransportParameter) -> bool,
        T: FromTransportParam,
    {
        self.s_tp.as_ref().and_then(|params| {
            search_transport_parameters(params, predicate).map(|t| T::from_param(t))
        })
    }

    pub(crate) fn get_peer_max_udp_payload_size(&self) -> Option<u16> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::MaxUdpPayloadSize(_))
        })
    }

    pub(crate) fn get_peer_idle_timeout(&self) -> Option<u64> {
        self.get_peer_transport_param(|item| matches!(item, TransportParameter::MaxIdleTimeout(_)))
    }

    pub(crate) fn get_peer_max_ack_delay(&self) -> Option<u16> {
        self.get_peer_transport_param(|item| matches!(item, TransportParameter::MaxAckDelay(_)))
    }

    pub(crate) fn get_peer_ack_delay_exponent(&self) -> Option<u8> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::AckDelayExponent(_))
        })
    }

    pub(crate) fn get_peer_initial_max_data(&self) -> Option<u64> {
        self.get_peer_transport_param(|item| matches!(item, TransportParameter::InitialMaxData(_)))
    }

    pub(crate) fn get_peer_initial_max_stream_data_bidi_local(&self) -> Option<u64> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::InitialMaxStreamDataBidiLocal(_))
        })
    }

    pub(crate) fn get_peer_initial_max_stream_data_bidi_remote(&self) -> Option<u64> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::InitialMaxStreamDataBidiRemote(_))
        })
    }

    pub(crate) fn get_peer_initial_max_stream_data_uni(&self) -> Option<u64> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::InitialMaxStreamDataUni(_))
        })
    }

    pub(crate) fn get_peer_initial_max_streams_bidi(&self) -> Option<u64> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::InitialMaxStreamsBidi(_))
        })
    }

    pub(crate) fn get_peer_initial_max_streams_uni(&self) -> Option<u64> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::InitialMaxStreamsUni(_))
        })
    }

    pub(crate) fn get_peer_stateless_reset_token(&self) -> Option<[u8; 16]> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::StatelessResetToken(_))
        })
    }

    pub(crate) fn get_peer_disable_active_migration(&self) -> Option<bool> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::DisableActiveMigration(_))
        })
    }

    pub(crate) fn get_peer_preferred_address(&self) -> Option<PreferredAddress> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::PreferredAddress(_))
        })
    }

    pub(crate) fn get_peer_active_connection_id_limit(&self) -> Option<u8> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::ActiveConnectionIdLimit(_))
        })
    }

    pub(crate) fn get_peer_original_destination_connection_id(&self) -> Option<Vec<u8>> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::OriginalDestinationConnectionId(_))
        })
    }

    pub(crate) fn get_peer_retry_source_connection_id(&self) -> Option<Vec<u8>> {
        self.get_peer_transport_param(|item| {
            matches!(item, TransportParameter::RetrySourceConnectionId(_))
        })
    }

    fn transport_parameters_serialize<W>(&self, cursor: &mut W) -> Result<()>
    where
        W: Write + Seek + Read,
    {
        self.c_tp.iter().try_for_each(|p| p.serialize(cursor))?;

        Ok(())
    }

    fn expect_tls_state(&self, expected_state: TlsClientState) -> Result<()> {
        if self.state != expected_state {
            return Err(TlsHandshakeError::new(
                TlsError::UnexpectedMessage,
                anyhow!(
                    "Invalid tls state {:?}, expected {:?}",
                    self.state,
                    expected_state
                ),
            )
            .into());
        }

        Ok(())
    }

    fn create_client_finished_message(&mut self, finished_hash: &[u8]) -> Result<Vec<u8>> {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
        let mut finished_msg = vec![];
        let mut cursor = Cursor::new(&mut finished_msg);

        cursor.write_u8(HandshakeType::Finished.as_u8())?;
        cursor.write_u24::<BigEndian>(TLS_FINISHED_LENGTH as u32)?;

        // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
        // verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))

        let base_key = self.handshake_client_secret.as_ref().ok_or_else(|| {
            anyhow!(
                "client_handshake_traffic_secret doesn't \
            exist when creating client finished message"
            )
        })?;

        let (hkdf_algo, hmac_algo) = match self.get_selected_cipher_suite()? {
            TLS_AES_256_GCM_SHA384 => (HKDF_SHA384, hmac::HMAC_SHA384),
            TLS_AES_128_GCM_SHA256 => (HKDF_SHA256, hmac::HMAC_SHA256),
            _ => {
                return Err(anyhow!(
                    "Unsupported cipher suite 0x{:x}",
                    self.get_selected_cipher_suite()?
                ))
            }
        };

        let prk = Prk::new_less_safe(hkdf_algo, base_key);
        let mut finished_key = vec![0u8; TLS_FINISHED_LENGTH as usize];
        hkdf_expand(&prk, &mut finished_key, TLS_FINISHED_SECRET_LABEL, &[])?;
        trace!("Generated finished key: {:x?}", finished_key);

        let mac = hmac::Key::new(hmac_algo, &finished_key);

        let tag = hmac::sign(&mac, finished_hash);

        finished_msg.write_all(tag.as_ref())?;
        trace!("Generated finished verify data: {:x?}", tag.as_ref());

        Ok(finished_msg)
    }

    fn create_client_hello_message(&mut self) -> Result<Vec<u8>> {
        self.expect_tls_state(TlsClientState::Uninitialized)?;

        let mut client_hello = vec![];
        let mut cursor = Cursor::new(&mut client_hello);

        trace!(
            "Creating ClientHello message at position {}",
            cursor.position()
        );

        cursor.write_u8(HandshakeType::ClientHello.as_u8())?;
        trace!(
            "Wrote ClientHello message type (0x01) at position {}",
            cursor.position() - 1
        );

        // Skip the packet length field
        let client_hello_len_pos = cursor.position();
        cursor.seek_relative(TLS_LENGTH_FIELD_SIZE as i64)?;
        trace!(
            "Reserved {TLS_LENGTH_FIELD_SIZE} bytes for ClientHello length at position {}",
            client_hello_len_pos
        );

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // uint16 ProtocolVersion;
        // opaque Random[32];
        // uint8 CipherSuite[2];    /* Cryptographic suite selector */
        // struct {
        //     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
        //     Random random;
        //     opaque legacy_session_id<0..32>;
        //     CipherSuite cipher_suites<2..2^16-2>;
        //     opaque legacy_compression_methods<1..2^8-1>;
        //     Extension extensions<8..2^16-1>;
        // } ClientHello;

        // the legacy_version field MUST be set to 0x0303, which is the version number for TLS 1.2.
        cursor.write_u16::<BigEndian>(TLS_12_VERSION)?;
        trace!(
            "Wrote legacy_version: 0x0303 at position {}",
            cursor.position() - 2
        );

        // https://datatracker.ietf.org/doc/html/rfc8446#appendix-C
        let mut rng = rand::thread_rng();
        let client_hello_random: [u8; TLS_HANDSHAKE_RANDOM_SIZE] = rng.gen();
        cursor.write_all(&client_hello_random)?;
        trace!(
            "Wrote client random at position {}: {:02x?}",
            cursor.position() - 32,
            client_hello_random
        );
        self.client_hello_random = Some(client_hello_random);

        // Empty legacy session ID
        cursor.write_u8(0)?;
        trace!(
            "Wrote empty legacy session ID (0x00) at position {}",
            cursor.position() - 1
        );

        let cipher_suites_len = 4;
        cursor.write_u16::<BigEndian>(cipher_suites_len)?;
        trace!(
            "Wrote cipher suites length (0x{:04x}) at position {}",
            cipher_suites_len,
            cursor.position() - 2
        );

        // only support TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384
        // TODO: support ChaCha20-Poly1305
        cursor.write_u16::<BigEndian>(TLS_AES_128_GCM_SHA256)?;
        cursor.write_u16::<BigEndian>(TLS_AES_256_GCM_SHA384)?;
        trace!(
            "Wrote cipher suite TLS_AES_128_GCM_SHA256(0x1301) and TLS_AES_256_GCM_SHA384 (0x1302) at position {}",
            cursor.position() - 2
        );

        // Empty legacy compression methods
        let compression_methods_len = 1;
        cursor.write_u8(compression_methods_len)?;
        cursor.write_u8(0)?;
        trace!(
            "Wrote legacy compression methods (len: 0x{:02x}, method: 0x00) at position {}",
            compression_methods_len,
            cursor.position() - 2
        );

        // TLS extensions
        let tls_extensions_len_pos = cursor.position();
        cursor.seek_relative(TLS_EXTS_LENGTH_FIELD_SIZE as i64)?;
        trace!(
            "Reserved {TLS_EXTS_LENGTH_FIELD_SIZE} bytes for extensions length at position {}",
            tls_extensions_len_pos
        );

        let tls_config = &self.tls_config;

        // ServerName extension
        trace!(
            "Writing ServerName extension for: {} at position {}",
            &tls_config.server_name,
            cursor.position()
        );
        if !tls_config.server_name.is_ascii() {
            return Err(anyhow!(
                "Invalid ssl config, server_name {} is not ASCII",
                &tls_config.server_name
            ));
        }
        cursor.write_u16::<BigEndian>(ExtensionType::ServerName.as_u16())?;
        let server_name_len = tls_config.server_name.len();
        let server_name_ext_len = server_name_len + 5;
        cursor.write_u16::<BigEndian>(server_name_ext_len as u16)?;
        let server_name_list_len = server_name_ext_len - 2;
        cursor.write_u16::<BigEndian>(server_name_list_len as u16)?;
        let server_name_host_type = 0;
        cursor.write_u8(server_name_host_type)?;
        cursor.write_u16::<BigEndian>(server_name_len as u16)?;
        cursor.write_all(tls_config.server_name.as_bytes())?;
        trace!("Completed ServerName extension");

        // SupportedGroups extension
        trace!(
            "Writing SupportedGroups extension at position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::SupportedGroups.as_u16())?;
        let support_groups_list_len = 2;
        // Only support x25519
        let support_group = TLS_ECDH_X25519;
        let support_groups_ext_len = support_groups_list_len + 2;
        cursor.write_u16::<BigEndian>(support_groups_ext_len as u16)?;
        cursor.write_u16::<BigEndian>(support_groups_list_len as u16)?;
        cursor.write_u16::<BigEndian>(support_group)?;
        trace!("Added x25519 (0x001d) to supported groups");

        // ALPN protocol names are ASCII strings, as defined by [RFC-1123].
        // The protocol names are case-sensitive, and must be valid UTF-8 sequences that are compatible with ASCII.
        trace!(
            "Writing ALPN protocol {} extension at position {}",
            tls_config.alpn,
            cursor.position()
        );
        cursor
            .write_u16::<BigEndian>(ExtensionType::ApplicationLayerProtocolNegotiation.as_u16())?;
        if !tls_config.alpn.is_ascii() {
            return Err(anyhow!(
                "Invalid ssl config, alpn {} is not ASCII",
                &tls_config.alpn
            ));
        }
        let alpn_len = tls_config.alpn.len();
        let alpn_ext_len = alpn_len + 1;
        let alpn_ext_len_dup = alpn_ext_len + 2;
        cursor.write_u16::<BigEndian>(alpn_ext_len_dup as u16)?;
        cursor.write_u16::<BigEndian>(alpn_ext_len as u16)?;
        cursor.write_u8(alpn_len as u8)?;
        cursor.write_all(tls_config.alpn.as_bytes())?;
        trace!("Completed ALPN extension");

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
        // only plan to support the signature algorithms were chosen by the certificate which is used in my blog
        trace!(
            "Writing SignatureAlgorithms extension at position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::SignatureAlgorithms.as_u16())?;
        // SHA256 + ECDSA
        let sha256_ecd_algorithms = 0x0403;
        let sha256_rsa_algorithms = 0x0804;
        let algo_len = 2 + 2;
        let algo_ext_len = algo_len + 2;
        cursor.write_u16::<BigEndian>(algo_ext_len as u16)?;
        cursor.write_u16::<BigEndian>(algo_len as u16)?;
        cursor.write_u16::<BigEndian>(sha256_ecd_algorithms)?;
        cursor.write_u16::<BigEndian>(sha256_rsa_algorithms)?;
        trace!("Added SHA256+ECDSA (0x0403) and SHA256+RSA (0x0804) to signature algorithms");

        // Since we only support x25519, we need to generate our keyshare for ECDH exchange
        // by the way, x25519 is an implementation for ECDH by using Curve 25519
        trace!(
            "Writing KeyShare extension at position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::KeyShare.as_u16())?;
        let rng = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|e| anyhow!("Ring failed to generate private key due to {e}"))?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|e| anyhow!("Ring failed to compute public key due to {e}"))?;
        let public_key_len = public_key.as_ref().len();
        let group = 0x001d; // x25519
        let key_share_len = public_key_len + 4;
        let key_share_ext_len = public_key_len + 6;
        cursor.write_u16::<BigEndian>(key_share_ext_len as u16)?;
        cursor.write_u16::<BigEndian>(key_share_len as u16)?;
        cursor.write_u16::<BigEndian>(group)?;
        cursor.write_u16::<BigEndian>(public_key_len as u16)?;
        cursor.write_all(public_key.as_ref())?;
        self.private_key = Some(private_key);

        // TODO: 0-RTT
        // If clients offer "pre_shared_key" without a "psk_key_exchange_modes" extension,
        // servers MUST abort the handshake
        // cursor.write_u16::<BigEndian>(ExtensionType::PskKeyExchangeModes.as_u16())?;
        // cursor.write_u16::<BigEndian>(ExtensionType::PreSharedKey.as_u16())?;

        // SupportedVersions extension
        trace!(
            "Writing SupportedVersions extension at position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::SupportedVersions.as_u16())?;
        let support_versions_list_len = 2;
        let support_version = 0x0304;
        let support_versions_ext_len = support_versions_list_len + 1;
        cursor.write_u16::<BigEndian>(support_versions_ext_len as u16)?;
        cursor.write_u8(support_versions_list_len as u8)?;
        cursor.write_u16::<BigEndian>(support_version)?;
        trace!("Added TLS 1.3 (0x0304) to supported versions");

        // Constructing QUIC tls extension
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-8.2
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18
        trace!(
            "Writing QUIC Transport Parameters extension at start position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::QuicTransportParameters.as_u16())?;
        let quic_tp_len_pos = cursor.position();
        cursor.seek_relative(TLS_QUIC_EXT_LENGTH_FIELD_SIZE as i64)?;
        self.transport_parameters_serialize(&mut cursor)?;
        trace!(
            "Completed QUIC transport parameters at position {}",
            cursor.position()
        );

        let cur_pos = cursor.position();
        let quic_ext_len = cur_pos - quic_tp_len_pos - TLS_QUIC_EXT_LENGTH_FIELD_SIZE as u64;
        write_cursor_bytes_with_pos(
            &mut cursor,
            quic_tp_len_pos,
            &u16::to_be_bytes(quic_ext_len as u16),
        )?;
        trace!(
            "Wrote QUIC extension length: {} at position {}",
            quic_ext_len,
            quic_tp_len_pos
        );

        let tls_exts_len = cur_pos - tls_extensions_len_pos - TLS_EXTS_LENGTH_FIELD_SIZE as u64;
        write_cursor_bytes_with_pos(
            &mut cursor,
            tls_extensions_len_pos,
            &u16::to_be_bytes(tls_exts_len as u16),
        )?;

        trace!(
            "Wrote total extensions length: {} at position {}",
            tls_exts_len,
            tls_extensions_len_pos
        );

        let client_hello_len = cur_pos - client_hello_len_pos - TLS_LENGTH_FIELD_SIZE as u64;
        let client_hello_len_bytes = &u32::to_be_bytes(client_hello_len as u32)[1..];
        write_cursor_bytes_with_pos(&mut cursor, client_hello_len_pos, client_hello_len_bytes)?;
        trace!(
            "Wrote total ClientHello length: {} at position {}, length hex data {:x?}",
            client_hello_len,
            client_hello_len_pos,
            client_hello_len_bytes,
        );

        trace!("Completed ClientHello packet, final position: {}", cur_pos);
        // Save the client hello message since the peer's cipher suite choice is unknown at this point
        self.client_hello_message = Some(cursor.get_ref()[..cursor.position() as usize].to_vec());

        self.state = TlsClientState::WaitServerHello;

        Ok(client_hello)
    }

    pub(crate) fn get_selected_cipher_suite(&self) -> Result<u16> {
        self.selected_chipher_suite
            .ok_or_else(|| anyhow!("No cipher suite selected"))
    }

    pub(crate) fn send(&mut self) -> Option<(Vec<u8>, QuicLevel)> {
        self.send_queue.pop_front()
    }

    //        Client                                           Server
    //
    // Key  ^ ClientHello
    // Exch | + key_share*
    //      | + signature_algorithms*
    //      | + psk_key_exchange_modes*
    //      v + pre_shared_key*       -------->
    //                                                   ServerHello  ^ Key
    //                                                  + key_share*  | Exch
    //                                             + pre_shared_key*  v
    //                                         {EncryptedExtensions}  ^  Server
    //                                         {CertificateRequest*}  v  Params
    //                                                {Certificate*}  ^
    //                                          {CertificateVerify*}  | Auth
    //                                                    {Finished}  v
    //                                <--------  [Application Data*]
    //      ^ {Certificate*}
    // Auth | {CertificateVerify*}
    //      v {Finished}              -------->
    //        [Application Data]      <------->  [Application Data]
    pub(crate) fn handle_tls_handshake(&mut self, crypto_buffer: &[u8]) -> Result<()> {
        let span = tracing::span!(
            tracing::Level::TRACE,
            "tls_handshake",
            from_state = ?self.state
        );
        let _enter = span.enter();

        let mut new_crypto_buffer: Vec<u8> = vec![];

        let length = crypto_buffer.len() as u64;
        let mut new_length = length;
        let mut cursor_new = if !self.recv_buf_store.is_empty() {
            new_length += self.recv_buf_store.len() as u64;
            new_crypto_buffer.extend(&self.recv_buf_store);
            new_crypto_buffer.extend(crypto_buffer);

            self.recv_buf_store.clear();

            Cursor::new(new_crypto_buffer.as_ref())
        } else {
            Cursor::new(crypto_buffer)
        };

        let cursor = &mut cursor_new;

        let start_pos = cursor.position();
        trace!(
            "Processing TLS handshake (start position: {}, length: {}, total length: {})",
            start_pos,
            length,
            new_length,
        );

        while cursor.position() - start_pos < new_length {
            let pos_before_read = cursor.position();
            let first_byte = cursor.read_u8().map_err(|e| {
                // Map I/O error to TLS decode error
                let err = anyhow!(e);
                warn!("TLS handshake error reading byte: {}", err);
                TlsHandshakeError::new(TlsError::DecodeError, err)
            })?;

            let handshake_type = HandshakeType::from_u8(first_byte).ok_or_else(|| {
                let msg = format!("Invalid TLS handshake type: 0x{first_byte:x}");
                warn!("TLS handshake error: {}", msg);
                TlsHandshakeError::new(TlsError::UnexpectedMessage, anyhow!(msg))
            })?;

            let remaining = new_length - (cursor.position() - start_pos);
            let msg_span = tracing::span!(
                parent: &span,
                tracing::Level::TRACE,
                "tls_message",
                message_type = ?handshake_type,
                current_state = ?self.state,
                position = pos_before_read,
                remaining_bytes = remaining
            );
            let _msg_enter = msg_span.enter();

            trace!(
                "Processing TLS handshake message {:?} at position {}",
                handshake_type,
                cursor.position(),
            );

            match handshake_type {
                HandshakeType::ServerHello => self.handle_server_hello(cursor)?,
                HandshakeType::EncryptedExtensions => self.handle_encrypted_extensions(cursor)?,
                HandshakeType::Certificate => self.handle_cerificate(cursor)?,
                HandshakeType::CertificateRequest => self.handle_cerificate_request(cursor)?,
                HandshakeType::CertificateVerify => self.handle_cerificate_verify(cursor)?,
                HandshakeType::Finished => self.handle_finished(cursor)?,
                HandshakeType::NewSessionTicket => self.handle_new_session_ticket(cursor)?,
                HandshakeType::KeyUpdate => {
                    // Endpoints MUST NOT send a TLS KeyUpdate message.
                    // Endpoints MUST treat the receipt of a TLS KeyUpdate message
                    // as a connection error of type 0x010a, equivalent to a fatal
                    // TLS alert of unexpected_message;
                    let msg = "TLS KeyUpdate message received - not allowed in QUIC";
                    warn!("TLS handshake error: {}", msg);
                    return Err(
                        TlsHandshakeError::new(TlsError::UnexpectedMessage, anyhow!(msg)).into(),
                    );
                }
                _ => {
                    let msg = format!("Unsupported handshake type: {handshake_type:?}");
                    warn!("TLS handshake error: {}", msg);
                    return Err(
                        TlsHandshakeError::new(TlsError::UnexpectedMessage, anyhow!(msg)).into(),
                    );
                }
            }

            let bytes_consumed = cursor.position() - pos_before_read;
            tracing::trace!(
                message_complete = true,
                bytes_consumed = bytes_consumed,
                new_position = cursor.position(),
                "Completed processing TLS message"
            );
        }

        if cursor.position() - start_pos != new_length {
            // TODO: support partial tls messages
            let msg = format!(
                "Invalid TLS packet, bad pos {}, begin pos {}, crypto frame new_length {}",
                cursor.position(),
                start_pos,
                new_length,
            );
            warn!("TLS handshake error: {}", msg);
            return Err(TlsHandshakeError::new(TlsError::DecodeError, anyhow!(msg)).into());
        }

        tracing::trace!(
            handshake_progress = ?self.state,
            bytes_processed = cursor.position() - start_pos,
            to_state = ?self.state,
            cipher_suite = ?self.selected_chipher_suite,
            "TLS handshake progress"
        );
        Ok(())
    }

    fn derive_application_tls_secret(&mut self, cipher_suite: u16) -> Result<Vec<u8>> {
        let (hash_algo, hash_size, dig_algo) = match cipher_suite {
            TLS_AES_256_GCM_SHA384 => (HKDF_SHA384, QUIC_SHA384_SECRET_LENGTH, &digest::SHA384),
            TLS_AES_128_GCM_SHA256 => (HKDF_SHA256, QUIC_SHA256_SECRET_LENGTH, &digest::SHA256),
            _ => return Err(anyhow!("Unsupported TLS cipher_suite {:x}", cipher_suite)),
        };

        // https://datatracker.ietf.org/doc/draft-ietf-tls-tls13-vectors/05/
        let context = digest::Context::new(dig_algo);
        let zero_hash_result = context.finish();
        trace!("Calculated early hash: {:x?}", zero_hash_result.as_ref());

        let salt = Salt::new(
            hash_algo,
            self.handshake_secret.as_ref().ok_or_else(|| {
                anyhow!("Cannot derive application secret: handshake secret not found")
            })?,
        );
        let prk = salt.extract(&vec![0u8; hash_size]);

        let hash_result = self
            .ap_context
            .take()
            .ok_or_else(|| anyhow!("Hash context not found"))?
            .finish();
        trace!("Calculated handshake hash: {:x?}", hash_result.as_ref());

        let mut client_ap_secret = vec![0u8; hash_size];
        hkdf_expand(
            &prk,
            &mut client_ap_secret,
            TLS_CLIENT_APPLICATION_SECRET_LABEL,
            hash_result.as_ref(),
        )?;

        let mut server_ap_secret = vec![0u8; hash_size];
        hkdf_expand(
            &prk,
            &mut server_ap_secret,
            TLS_SERVER_APPLICATION_SECRET_LABEL,
            hash_result.as_ref(),
        )?;

        trace!(
            "Generated shared secret (size: {}, data: {:x?})",
            hash_size,
            &client_ap_secret
        );

        trace!(
            "Generated shared secret (size: {}, data: {:x?})",
            hash_size,
            &server_ap_secret
        );

        if let Some(ref mut key_log_file) = self.ssl_key_file {
            let cli_random_str: String = self
                .client_hello_random
                .as_ref()
                .ok_or_else(|| anyhow!("Client hello random not available"))?
                .iter()
                .fold(
                    String::with_capacity(TLS_HANDSHAKE_RANDOM_SIZE * 2),
                    |mut acc, &byte| {
                        acc.push_str(&format!("{byte:02x}"));
                        acc
                    },
                );
            let cli_ap_str: String = client_ap_secret.iter().fold(
                String::with_capacity(hash_size * 2),
                |mut acc, &byte| {
                    acc.push_str(&format!("{byte:02x}"));
                    acc
                },
            );
            let ser_ap_str: String = server_ap_secret.iter().fold(
                String::with_capacity(hash_size * 2),
                |mut acc, &byte| {
                    acc.push_str(&format!("{byte:02x}"));
                    acc
                },
            );

            if let Err(e) = Self::write_log_entry(
                key_log_file,
                TLS_CLIENT_TRAFFIC_SECRET_0,
                &cli_random_str,
                &cli_ap_str,
            ) {
                warn!("Cannot write to SSL key log file due to error: {e}");
            }

            if let Err(e) = Self::write_log_entry(
                key_log_file,
                TLS_SERVER_TRAFFIC_SECRET_0,
                &cli_random_str,
                &ser_ap_str,
            ) {
                warn!("Cannot write to SSL key log file due to error: {e}");
            }
        }

        self.application_client_secret = Some(client_ap_secret);
        self.application_server_secret = Some(server_ap_secret);

        let all_hs_hash = Vec::from(hash_result.as_ref());

        Ok(all_hs_hash)
    }

    pub(crate) fn append_key_update_sslkey(&mut self, cs: &[u8], ss: &[u8]) -> Result<()> {
        let key_log_file = match self.ssl_key_file.as_mut() {
            Some(file) => file,
            None => return Ok(()),
        };
        let cli_random_str: String = self
            .client_hello_random
            .as_ref()
            .ok_or_else(|| anyhow!("Client hello random not available"))?
            .iter()
            .fold(
                String::with_capacity(TLS_HANDSHAKE_RANDOM_SIZE * 2),
                |mut acc, &byte| {
                    acc.push_str(&format!("{byte:02x}"));
                    acc
                },
            );

        let cs_len = cs.len();
        let cli_str: String =
            cs.iter()
                .fold(String::with_capacity(cs_len * 2), |mut acc, &byte| {
                    acc.push_str(&format!("{byte:02x}"));
                    acc
                });
        let secret_label = format!("{}{}", TLS_CLIENT_TRAFFIC_SECRET, self.ssl_key_update_times);
        if let Err(e) =
            Self::write_log_entry(key_log_file, &secret_label, &cli_random_str, &cli_str)
        {
            warn!("Cannot write to SSL key log file due to error: {e}");
        }

        let ss_len = ss.len();
        let ser_str: String =
            ss.iter()
                .fold(String::with_capacity(ss_len * 2), |mut acc, &byte| {
                    acc.push_str(&format!("{byte:02x}"));
                    acc
                });
        let secret_label = format!("{}{}", TLS_SERVER_TRAFFIC_SECRET, self.ssl_key_update_times);
        if let Err(e) =
            Self::write_log_entry(key_log_file, &secret_label, &cli_random_str, &ser_str)
        {
            warn!("Cannot write to SSL key log file due to error: {e}");
        }

        Ok(())
    }

    fn handle_finished(&mut self, cursor: &mut Cursor<&[u8]>) -> Result<()> {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
        self.expect_tls_state(TlsClientState::WaitFinished)?;

        let start_pos = cursor
            .position()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Cursor position underflowed {}", cursor.position()))?;
        let length = cursor.read_u24::<BigEndian>()?;
        let remain_bytes = remaining_bytes(cursor)?;

        if length > remain_bytes as u32 {
            info!(
                "Received incomplete finished message (length: {}, remaining bytes: {}, start position: {})",
                length,
                remain_bytes,
                start_pos
            );
            self.recv_buf_store
                .extend(&cursor.get_ref()[start_pos as usize..]);
            cursor.seek_relative(remain_bytes as i64)?;
            return Ok(());
        }

        trace!(
            "Received finished message (length: {}, position: {})",
            length,
            cursor.position()
        );

        // TODO: Recipients of Finished messages MUST verify that the contents are
        // correct and if incorrect MUST terminate the connection with a
        // "decrypt_error" alert.
        cursor.seek_relative(length as i64)?;

        self.ap_context
            .as_mut()
            .ok_or_else(|| anyhow!("Hash context not found"))?
            .update(&cursor.get_ref()[start_pos as usize..cursor.position() as usize]);

        let finished_hash =
            self.derive_application_tls_secret(self.get_selected_cipher_suite()?)?;

        self.state = TlsClientState::Connected;

        // Preparing our client handshake finished message
        let client_finished_msg = self.create_client_finished_message(&finished_hash)?;

        self.send_queue
            .push_back((client_finished_msg, QuicLevel::Handshake));

        Ok(())
    }

    fn handle_new_session_ticket(&mut self, cursor: &mut Cursor<&[u8]>) -> Result<()> {
        self.expect_tls_state(TlsClientState::Connected)?;
        let start_pos = cursor
            .position()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Cursor position underflowed {}", cursor.position()))?;
        let length = cursor.read_u24::<BigEndian>()?;
        let remain_bytes = remaining_bytes(cursor)?;

        if length > remain_bytes as u32 {
            info!(
                "Received incomplete new session ticket message (length: {}, remaining bytes: {}, start position: {})",
                length,
                remain_bytes,
                start_pos
            );
            self.recv_buf_store
                .extend(&cursor.get_ref()[start_pos as usize..]);
            cursor.seek_relative(remain_bytes as i64)?;
            return Ok(());
        }

        // TODO: support 0rtt
        cursor.seek_relative(length as i64)?;
        trace!(
            "Received new session ticket from peer (length: {}, current position: {}). Ignoring for now.",
            length,
            cursor.position()
        );

        Ok(())
    }

    fn handle_cerificate(&mut self, cursor: &mut Cursor<&[u8]>) -> Result<()> {
        self.expect_tls_state(TlsClientState::WaitCertificate)?;
        let start_pos = cursor
            .position()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Cursor position underflowed {}", cursor.position()))?;
        let length = cursor.read_u24::<BigEndian>()?;
        let remain_bytes = remaining_bytes(cursor)?;

        if length > remain_bytes as u32 {
            info!(
                "Received incomplete certificate message (length: {}, remaining bytes: {}, start position: {})",
                length,
                remain_bytes,
                start_pos
            );
            self.recv_buf_store
                .extend(&cursor.get_ref()[start_pos as usize..]);
            cursor.seek_relative(remain_bytes as i64)?;
            return Ok(());
        }

        // TODO: Verify peer's certificate
        cursor.seek_relative(length as i64)?;
        trace!(
            "Received certificate from peer (length: {}, current position: {}). Ignoring verification for now.",
            length,
            cursor.position()
        );

        self.ap_context
            .as_mut()
            .ok_or_else(|| anyhow!("Hash context not found"))?
            .update(&cursor.get_ref()[start_pos as usize..cursor.position() as usize]);

        self.state = TlsClientState::WaitCertificateVerify;

        Ok(())
    }

    fn handle_cerificate_verify(&mut self, cursor: &mut Cursor<&[u8]>) -> Result<()> {
        self.expect_tls_state(TlsClientState::WaitCertificateVerify)?;
        let start_pos = cursor
            .position()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Cursor position underflowed {}", cursor.position()))?;
        let length = cursor.read_u24::<BigEndian>()?;
        let remain_bytes = remaining_bytes(cursor)?;

        if length > remain_bytes as u32 {
            info!(
                "Received incomplete certificate verify message (length: {}, remaining bytes: {}, start position: {})",
                length,
                remain_bytes,
                start_pos
            );
            self.recv_buf_store
                .extend(&cursor.get_ref()[start_pos as usize..]);
            cursor.seek_relative(remain_bytes as i64)?;
            return Ok(());
        }

        // TODO: Verify peer's certificate
        cursor.seek_relative(length as i64)?;
        trace!(
            "Received certificate verify from peer (length: {}, current position: {}). Ignoring verification for now.",
            length,
            cursor.position()
        );

        self.ap_context
            .as_mut()
            .ok_or_else(|| anyhow!("Hash context not found"))?
            .update(&cursor.get_ref()[start_pos as usize..cursor.position() as usize]);

        self.state = TlsClientState::WaitFinished;

        Ok(())
    }

    fn handle_cerificate_request(&mut self, _cursor: &mut Cursor<&[u8]>) -> Result<()> {
        panic!("Never plan to support this, haha");
    }

    fn handle_server_hello(&mut self, cursor: &mut Cursor<&[u8]>) -> Result<()> {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
        // struct {
        //       ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
        //       Random random;
        //       opaque legacy_session_id_echo<0..32>;
        //       CipherSuite cipher_suite;
        //       uint8 legacy_compression_method = 0;
        //       Extension extensions<6..2^16-1>;
        //   } ServerHello;

        self.expect_tls_state(TlsClientState::WaitServerHello)?;

        let start_pos = cursor
            .position()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Cursor position underflowed {}", cursor.position()))?;
        let length = cursor.read_u24::<BigEndian>()?;

        let remain_bytes = remaining_bytes(cursor)?;

        if length > remain_bytes as u32 {
            info!(
                "Received incomplete server hello message (length: {}, remaining bytes: {}, start position: {})",
                length,
                remain_bytes,
                start_pos
            );
            self.recv_buf_store
                .extend(&cursor.get_ref()[start_pos as usize..]);
            cursor.seek_relative(remain_bytes as i64)?;
            return Ok(());
        }

        let legacy_version = cursor.read_u16::<BigEndian>()?;
        if legacy_version != TLS_12_VERSION {
            return Err(anyhow!(
                "Invalid TLS server hello: unsupported legacy version 0x{:x}",
                legacy_version
            ));
        }

        let mut random = [0u8; TLS_HANDSHAKE_RANDOM_SIZE];
        cursor.read_exact(&mut random)?;

        let legacy_session_id = cursor.read_u8()?;

        // only support TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384
        let selected_chipher_suite = cursor.read_u16::<BigEndian>()?;
        self.selected_chipher_suite = Some(selected_chipher_suite);

        // Compression methods must be null (0)
        let _ = cursor.read_u8()?;

        trace!(
            "Processing server hello (length: {}, version: 0x{:x}, random: 0x{:x?}, session id: {}, cipher suite: 0x{:x})",
            length,
            legacy_version,
            &random,
            legacy_session_id,
            selected_chipher_suite
        );

        let exts_len = cursor.read_u16::<BigEndian>()?;
        let ext_begin_pos = cursor.position();
        trace!(
            "Processing server hello extensions (start position: {}, extensions length: {})",
            ext_begin_pos,
            exts_len
        );
        while cursor.position() - ext_begin_pos < exts_len as u64 {
            let ext_type = cursor.read_u16::<BigEndian>()?;
            let ext_type = ExtensionType::from_u16(ext_type);

            match ext_type {
                ExtensionType::KeyShare => {
                    // TODO: Verify extension length
                    let _ = cursor.read_u16::<BigEndian>()?;
                    // Group must be x25519 since it's the only algorithm supported here
                    let group = cursor.read_u16::<BigEndian>()?;
                    if group != TLS_ECDH_X25519 {
                        return Err(anyhow!(
                            "Invalid TLS server hello: unsupported key share group 0x{:x} for extension {:?}",
                            group,
                            ext_type,
                        ));
                    }
                    let key_exchange_len = cursor.read_u16::<BigEndian>()?;
                    let key_ex_start_pos = cursor.position() as usize;
                    self.derive_handshake_tls_secret(
                        &cursor.get_ref()
                            [key_ex_start_pos..key_ex_start_pos + key_exchange_len as usize],
                        &cursor.get_ref()
                            [start_pos as usize..ext_begin_pos as usize + exts_len as usize],
                        selected_chipher_suite,
                    )?;
                    cursor.seek_relative(key_exchange_len as i64)?;
                    info!(
                        "Processing key share extension from server hello (group: 0x{:x}, key exchange length: {}, start position: {})",
                        group,
                        key_exchange_len,
                        key_ex_start_pos
                    );
                }
                ExtensionType::SupportedVersions => {
                    // https://www.rfc-editor.org/rfc/rfc9001.html#section-4.2
                    let ext_len = cursor.read_u16::<BigEndian>()?;
                    if ext_len != 2 {
                        return Err(anyhow!(
                            "Invalid TLS server hello: incorrect length {} for extension {:?}",
                            ext_len,
                            ext_type,
                        ));
                    }
                    let supported_version = cursor.read_u16::<BigEndian>()?;
                    if supported_version != TLS_13_VERSION {
                        return Err(anyhow!(
                            "Invalid TLS server hello: unsupported version 0x{:x} for extension {:?}",
                            supported_version,
                            ext_type,
                        ));
                    }
                }
                _ => panic!("Unexpected extension in server hello: {ext_type:?}"),
            }
        }

        self.state = TlsClientState::WaitEncryptedExtensions;

        Ok(())
    }

    fn handle_encrypted_extensions(&mut self, cursor: &mut Cursor<&[u8]>) -> Result<()> {
        self.expect_tls_state(TlsClientState::WaitEncryptedExtensions)?;
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1

        let start_pos = cursor
            .position()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("Cursor position underflowed {}", cursor.position()))?;
        let length = cursor.read_u24::<BigEndian>()?;
        let remain_bytes = remaining_bytes(cursor)?;

        if length > remain_bytes as u32 {
            info!(
                "Received incomplete encrypted extensions message (length: {}, remaining bytes: {}, start position: {})",
                length,
                remain_bytes,
                start_pos
            );
            self.recv_buf_store
                .extend(&cursor.get_ref()[start_pos as usize..]);
            cursor.seek_relative(remain_bytes as i64)?;
            return Ok(());
        }

        let exts_len = cursor.read_u16::<BigEndian>()?;
        let ext_begin_pos = cursor.position();
        trace!(
            "Processing encrypted extensions (start position: {}, extensions length: {}, total length: {})",
            ext_begin_pos,
            exts_len,
            length
        );

        while cursor.position() - ext_begin_pos < exts_len as u64 {
            let ext_type = cursor.read_u16::<BigEndian>()?;
            let ext_type = ExtensionType::from_u16(ext_type);
            trace!(
                "Processing extension type {:?} (position: {}, length: {}, start: {})",
                ext_type,
                cursor.position(),
                exts_len,
                ext_begin_pos
            );

            match ext_type {
                ExtensionType::ApplicationLayerProtocolNegotiation => {
                    let alpn_len = cursor.read_u16::<BigEndian>()?;
                    let alpn_ext_len = cursor.read_u16::<BigEndian>()?;
                    let alpn_str_len = cursor.read_u8()?;
                    let mut alpn_bytes = vec![0u8; alpn_str_len as usize];
                    cursor.read_exact(&mut alpn_bytes)?;
                    // ALPN protocol names are ASCII strings, as defined by [RFC-1123].
                    let alpn_str = String::from_utf8(alpn_bytes)?;
                    if self.tls_config.alpn != alpn_str {
                        return Err(anyhow!(
                            "Invalid ALPN (received: {}, expected: {})",
                            alpn_str,
                            self.tls_config.alpn
                        ));
                    }
                    trace!(
                        "Received ALPN {} from peer (ALPN length: {}, extension length: {}, string length: {})",
                        alpn_str,
                        alpn_len,
                        alpn_ext_len,
                        alpn_str_len
                    );
                }
                ExtensionType::QuicTransportParameters => {
                    let tp_len = cursor.read_u16::<BigEndian>()?;
                    match parse_server_transport_parameters(cursor, tp_len) {
                        Ok(transport_params) => {
                            self.s_tp = Some(transport_params);
                            trace!("Received server QUIC transport parameters {:?}", self.s_tp);
                        }
                        Err(_e) => {
                            // Convert anyhow error to QuicConnectionErrorCode
                            let transport_param_error =
                                crate::error_code::QuicConnectionErrorCode::create_transport_error_code(
                                    u64::from(crate::error_code::TransportErrorCode::TransportParameterError),
                                    Some(QuicFrameType::Crypto as u64), // CRYPTO frame type
                                );
                            return Err(anyhow::Error::from(transport_param_error));
                        }
                    }
                }
                ExtensionType::ServerName => {
                    // https://datatracker.ietf.org/doc/html/rfc6066#section-3
                    let server_name_ext_len = cursor.read_u16::<BigEndian>()?;
                    if server_name_ext_len == 0 {
                        trace!("Received empty server name extension");
                        continue;
                    }
                    let server_ext_start_pos = cursor.position();
                    let server_name_list_len = cursor.read_u16::<BigEndian>()?;
                    let server_name_type = cursor.read_u8()?;
                    let server_name_len = cursor.read_u16::<BigEndian>()?;
                    let mut server_name = vec![0u8; server_name_len as usize];
                    trace!("server_name_ext_len {server_name_ext_len}, server_name_list_len {server_name_list_len}, \
                        server_name_type {server_name_type}, server_name_len {server_name_len}");
                    cursor.read_exact(&mut server_name)?;
                    let server_name_str = String::from_utf8(server_name)?;
                    trace!("Received server name {} from server", server_name_str);
                    if server_ext_start_pos + server_name_ext_len as u64 != cursor.position() {
                        // TODO: handle multiple server names
                        panic!("Multiple server names are not supported");
                    }
                }
                _ => panic!("Unexpected extension in encrypted extensions: {ext_type:?}"),
            }
        }

        if cursor.position() == ext_begin_pos + exts_len as u64 {
            self.ap_context
                .as_mut()
                .ok_or_else(|| anyhow!("Hash context not found"))?
                .update(&cursor.get_ref()[start_pos as usize..cursor.position() as usize]);

            self.state = TlsClientState::WaitCertificate;
        } else {
            // TODO: support partial tls messages
            return Err(anyhow!(
                "Invalid encrypted extensions: mismatched position (current: {}, start: {}, length: {})",
                cursor.position(),
                ext_begin_pos,
                exts_len,
            ));
        }

        Ok(())
    }

    fn write_log_entry(
        key_log_file: &mut dyn Write,
        tls_secret: &str,
        random_str: &str,
        hs_str: &str,
    ) -> std::io::Result<()> {
        key_log_file.write_all(tls_secret.as_bytes())?;
        key_log_file.write_all(b" ")?;

        key_log_file.write_all(random_str.as_bytes())?;
        key_log_file.write_all(b" ")?;

        key_log_file.write_all(hs_str.as_bytes())?;

        key_log_file.write_all(b"\n")?;

        Ok(())
    }

    fn derive_handshake_tls_secret(
        &mut self,
        peer_key_shared: &[u8],
        server_hello_message: &[u8],
        cipher_suite: u16,
    ) -> Result<()> {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-7.4
        // https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.1.1
        // Calculate shared secret by ECDHE
        let peer_public_key = UnparsedPublicKey::new(&X25519, peer_key_shared);
        let shared_secret: Vec<u8> = agree_ephemeral(
            // Private key is only for this, so we can take it
            self.private_key.take().ok_or_else(|| {
                anyhow!("Client private key not available for shared secret calculation")
            })?,
            &peer_public_key,
            |shared_secret| shared_secret.to_vec(),
        )
        .map_err(|e| anyhow!("Failed to calculate shared secret: {e}"))?;
        trace!(
            "Generated shared secret (size: {}, data: {:x?})",
            shared_secret.len(),
            &shared_secret
        );

        // https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
        //-  HKDF-Extract is drawn as taking the Salt argument from the top and
        //   the IKM argument from the left, with its output to the bottom and
        //   the name of the output on the right.
        //-  Derive-Secret's Secret argument is indicated by the incoming
        //   arrow.  For instance, the Early Secret is the Secret for
        //   generating the client_early_traffic_secret.
        //-  "0" indicates a string of Hash.length bytes set to zero.
        //              0
        //              |
        //              v
        //    PSK ->  HKDF-Extract = Early Secret
        //              |
        //              +-----> Derive-Secret(., "ext binder" | "res binder", "")
        //              |                     = binder_key
        //              |
        //              +-----> Derive-Secret(., "c e traffic", ClientHello)
        //              |                     = client_early_traffic_secret
        //              |
        //              +-----> Derive-Secret(., "e exp master", ClientHello)
        //              |                     = early_exporter_master_secret
        //              v
        //        Derive-Secret(., "derived", "")
        //              |
        //              v
        //    (EC)DHE -> HKDF-Extract = Handshake Secret
        //              |
        //              +-----> Derive-Secret(., "c hs traffic",
        //              |                     ClientHello...ServerHello)
        //              |                     = client_handshake_traffic_secret
        //              |
        //              +-----> Derive-Secret(., "s hs traffic",
        //              |                     ClientHello...ServerHello)
        //              |                     = server_handshake_traffic_secret
        //              v
        //        Derive-Secret(., "derived", "")
        //              |
        //              v
        //    0 -> HKDF-Extract = Master Secret
        //              |
        //              +-----> Derive-Secret(., "c ap traffic",
        //              |                     ClientHello...server Finished)
        //              |                     = client_application_traffic_secret_0
        //              |
        //              +-----> Derive-Secret(., "s ap traffic",
        //              |                     ClientHello...server Finished)
        //              |                     = server_application_traffic_secret_0
        //              |
        //              +-----> Derive-Secret(., "exp master",
        //              |                     ClientHello...server Finished)
        //              |                     = exporter_master_secret
        //              |
        //              +-----> Derive-Secret(., "res master",
        //                                    ClientHello...client Finished)
        //                                    = resumption_master_secret
        let client_hello_message = self
            .client_hello_message
            .as_ref()
            .ok_or_else(|| anyhow!("Client hello message not available for TLS key derivation"))?;

        let (hash_algo, hash_size, dig_algo) = match cipher_suite {
            TLS_AES_256_GCM_SHA384 => (HKDF_SHA384, QUIC_SHA384_SECRET_LENGTH, &digest::SHA384),
            TLS_AES_128_GCM_SHA256 => (HKDF_SHA256, QUIC_SHA256_SECRET_LENGTH, &digest::SHA256),
            _ => return Err(anyhow!("Unsupported TLS cipher_suite {:x}", cipher_suite)),
        };

        // https://datatracker.ietf.org/doc/draft-ietf-tls-tls13-vectors/05/
        let context = digest::Context::new(dig_algo);
        let zero_hash_result = context.finish();
        trace!("Calculated early hash: {:x?}", zero_hash_result.as_ref());

        let early_salt = Salt::new(hash_algo, &vec![0u8; hash_size]);
        // TODO: Support 0-rtt
        let early_prk = early_salt.extract(&vec![0u8; hash_size]);

        let mut early_derived_secret = vec![0u8; hash_size];
        hkdf_expand(
            &early_prk,
            &mut early_derived_secret,
            TLS_DERIVED_SECRET_LABEL,
            zero_hash_result.as_ref(),
        )?;
        trace!(
            "Generated early PRK {:?} and early derived secret (size: {}, data: {:x?})",
            early_prk,
            early_derived_secret.len(),
            &early_derived_secret
        );

        let hs_salt = Salt::new(hash_algo, &early_derived_secret);
        let hs_prk = hs_salt.extract(&shared_secret);

        // Derive-Secret(Secret, Label, Messages) =
        //    HKDF-Expand-Label(Secret, Label,
        //        Transcript-Hash(Messages), Hash.length)
        // The Hash function used by Transcript-Hash and HKDF is the cipher
        // suite hash algorithm.  Hash.length is its output length in bytes.
        // Messages is the concatenation of the indicated handshake messages,
        // including the handshake message type and length fields, but not
        // including record layer headers.  Note that in some cases a zero-
        // length Context (indicated by "") is passed to HKDF-Expand-Label.  The
        // labels specified in this document are all ASCII strings and do not
        // include a trailing NUL byte.
        let mut context = digest::Context::new(dig_algo);
        context.update(client_hello_message);
        context.update(server_hello_message);
        let hash_result = context.finish();

        let mut context = digest::Context::new(dig_algo);
        context.update(client_hello_message);
        context.update(server_hello_message);
        self.ap_context = Some(context);
        trace!("Calculated handshake hash: {:x?}", hash_result.as_ref());

        let mut client_hs_secret = vec![0u8; hash_size];
        hkdf_expand(
            &hs_prk,
            &mut client_hs_secret,
            TLS_CLIENT_HANDSHAKE_SECRET_LABEL,
            hash_result.as_ref(),
        )?;
        let mut server_hs_secret = vec![0u8; hash_size];
        hkdf_expand(
            &hs_prk,
            &mut server_hs_secret,
            TLS_SERVER_HANDSHAKE_SECRET_LABEL,
            hash_result.as_ref(),
        )?;

        trace!(
            "Generated client tls handshake secret size {} hex data {:x?}",
            hash_size,
            &client_hs_secret
        );

        trace!(
            "Generated server tls handshake secret size {} hex data {:x?}",
            hash_size,
            &server_hs_secret
        );

        if let Some(ref mut key_log_file) = self.ssl_key_file {
            let cli_random_str: String = self
                .client_hello_random
                .as_ref()
                .ok_or_else(|| anyhow!("Client hello random not available"))?
                .iter()
                .fold(
                    String::with_capacity(TLS_HANDSHAKE_RANDOM_SIZE * 2),
                    |mut acc, &byte| {
                        acc.push_str(&format!("{byte:02x}"));
                        acc
                    },
                );
            let cli_hs_str: String = client_hs_secret.iter().fold(
                String::with_capacity(hash_size * 2),
                |mut acc, &byte| {
                    acc.push_str(&format!("{byte:02x}"));
                    acc
                },
            );
            let ser_hs_str: String = server_hs_secret.iter().fold(
                String::with_capacity(hash_size * 2),
                |mut acc, &byte| {
                    acc.push_str(&format!("{byte:02x}"));
                    acc
                },
            );

            if let Err(e) = Self::write_log_entry(
                key_log_file,
                TLS_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                &cli_random_str,
                &cli_hs_str,
            ) {
                warn!("Cannot write to SSL key log file due to error: {e}");
            }

            if let Err(e) = Self::write_log_entry(
                key_log_file,
                TLS_SERVER_HANDSHAKE_TRAFFIC_SECRET,
                &cli_random_str,
                &ser_hs_str,
            ) {
                warn!("Cannot write to SSL key log file due to error: {e}");
            }
        }

        self.handshake_client_secret = Some(client_hs_secret);
        self.handshake_server_secret = Some(server_hs_secret);

        let mut handshake_secret = vec![0u8; hash_size];
        hkdf_expand(
            &hs_prk,
            &mut handshake_secret,
            TLS_DERIVED_SECRET_LABEL,
            zero_hash_result.as_ref(),
        )?;
        trace!(
            "Generated handshake secret size {} hex data {:x?}",
            hash_size,
            &handshake_secret
        );
        self.handshake_secret = Some(handshake_secret);

        Ok(())
    }
}

// Define a custom error type for TLS handshake errors
#[derive(Debug)]
pub struct TlsHandshakeError {
    tls_error: TlsError,
    source: anyhow::Error,
}

impl TlsHandshakeError {
    pub fn new(tls_error: TlsError, source: anyhow::Error) -> Self {
        Self { tls_error, source }
    }

    pub fn get_tls_error(&self) -> TlsError {
        self.tls_error
    }
}

impl std::fmt::Display for TlsHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TLS handshake error: {} ({})",
            self.source,
            self.tls_error.to_error_message()
        )
    }
}

impl std::error::Error for TlsHandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}
