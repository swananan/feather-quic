use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::{Cursor, Read, Seek, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use tracing::{info, trace, warn};

use crate::config::QuicConfig;
use crate::connection::QUIC_STATELESS_RESET_TOKEN_SIZE;
use crate::tls::TlsContext;
use crate::utils::{decode_variable_length, encode_variable_length, get_variable_length};

pub const MAX_UDP_PAYLOAD_SIZE: u16 = 65527;
pub const MIN_UDP_PAYLOAD_SIZE: u16 = 1200;

// Validate according to RFC 9000: active_connection_id_limit must be at least 2
// https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.30.1
pub const MIN_ACTIVE_CONNECTION_ID_LIMIT: u8 = 2;

// Transport Parameter Type IDs as defined in RFC 9000 Section 18.2
pub(crate) mod transport_param_type {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0A;
    pub const MAX_ACK_DELAY: u64 = 0x0B;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0C;
    pub const PREFERRED_ADDRESS: u64 = 0x0D;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0E;
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0F;
    pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
    pub const GREASE_QUIC_BIT: u64 = 0x2ab2;
    pub const GREASE: u64 = 0x33afd753a0b2efbb;
}

#[allow(dead_code)]
// https://www.rfc-editor.org/rfc/rfc9000.html#section-18
pub(crate) enum TransportParameter {
    // This parameter is the value of the Destination Connection ID field
    // from the first Initial packet sent by the client;
    // see Section 7.3. This transport parameter is only sent by a server.
    OriginalDestinationConnectionId(Vec<u8>),

    // The maximum idle timeout is a value in milliseconds that is encoded as an integer; see (Section 10.1).
    // Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0.
    MaxIdleTimeout(u64), // in milliseconds

    // A stateless reset token is used in verifying a stateless reset; see Section 10.3.
    // This parameter is a sequence of 16 bytes. This transport parameter MUST NOT be sent by a client but MAY be sent by a server.
    // A server that does not send this transport parameter cannot use stateless reset (Section 10.3)
    // for the connection ID negotiated during the handshake.
    StatelessResetToken([u8; QUIC_STATELESS_RESET_TOKEN_SIZE as usize]),

    // The maximum UDP payload size parameter is an integer value that limits the size of UDP payloads
    // that the endpoint is willing to receive.
    // UDP datagrams with payloads larger than this limit are not likely to be processed by the receiver.
    MaxUdpPayloadSize(u16),

    InitialMaxData(u64),

    // This parameter is an integer value specifying the initial flow control limit for locally initiated bidirectional streams.
    // This limit applies to newly created bidirectional streams opened by the endpoint that sends the transport parameter.
    // In client transport parameters, this applies to streams with an identifier with the least significant two
    // bits set to 0x00; in server transport parameters, this applies to streams with the least significant two bits set to 0x01.
    InitialMaxStreamDataBidiLocal(u64),

    // This parameter is an integer value specifying the initial flow control limit for peer-initiated bidirectional streams.
    // This limit applies to newly created bidirectional streams opened by the endpoint that receives the transport parameter.
    // In client transport parameters, this applies to streams with an identifier with the least significant two bits set to 0x01;
    // in server transport parameters, this applies to streams with the least significant two bits set to 0x00
    InitialMaxStreamDataBidiRemote(u64),

    InitialMaxStreamDataUni(u64),

    InitialMaxStreamsBidi(u64),

    InitialMaxStreamsUni(u64),

    AckDelayExponent(u8),

    // The maximum acknowledgment delay is an integer value indicating the maximum amount of time in milliseconds by
    // which the endpoint will delay sending acknowledgments. This value SHOULD include the receiver's expected delays in alarms firing.
    // For example, if a receiver sets a timer for 5ms and alarms commonly fire up to 1ms late, then it should send a max_ack_delay of 6ms.
    // If this value is absent, a default of 25 milliseconds is assumed. Values of 1 << 14 or greater are invalid.
    MaxAckDelay(u16),

    DisableActiveMigration(bool),

    PreferredAddress(PreferredAddress),

    ActiveConnectionIdLimit(u8),

    InitialSourceConnectionId(Vec<u8>),

    RetrySourceConnectionId(Vec<u8>),
}

#[derive(Debug, Clone)]
pub(crate) struct PreferredAddress {
    ipv4_address: Ipv4Addr,
    ipv4_port: u16,
    ipv6_address: Ipv6Addr,
    ipv6_port: u16,
    connection_id_length: u8,
    connection_id: Vec<u8>,
    stateless_reset_token: [u8; 16],
}

impl fmt::Debug for TransportParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportParameter::OriginalDestinationConnectionId(v) => f
                .debug_tuple("OriginalDestinationConnectionId")
                .field(&format_args!("{v:02x?}"))
                .finish(),
            TransportParameter::MaxIdleTimeout(v) => {
                f.debug_tuple("MaxIdleTimeout").field(v).finish()
            }
            TransportParameter::StatelessResetToken(v) => f
                .debug_tuple("StatelessResetToken")
                .field(&format_args!("{v:02x?}"))
                .finish(),
            TransportParameter::MaxUdpPayloadSize(v) => {
                f.debug_tuple("MaxUdpPayloadSize").field(v).finish()
            }
            TransportParameter::InitialMaxData(v) => {
                f.debug_tuple("InitialMaxData").field(v).finish()
            }
            TransportParameter::InitialMaxStreamDataBidiLocal(v) => f
                .debug_tuple("InitialMaxStreamDataBidiLocal")
                .field(v)
                .finish(),
            TransportParameter::InitialMaxStreamDataBidiRemote(v) => f
                .debug_tuple("InitialMaxStreamDataBidiRemote")
                .field(v)
                .finish(),
            TransportParameter::InitialMaxStreamDataUni(v) => {
                f.debug_tuple("InitialMaxStreamDataUni").field(v).finish()
            }
            TransportParameter::InitialMaxStreamsBidi(v) => {
                f.debug_tuple("InitialMaxStreamsBidi").field(v).finish()
            }
            TransportParameter::InitialMaxStreamsUni(v) => {
                f.debug_tuple("InitialMaxStreamsUni").field(v).finish()
            }
            TransportParameter::AckDelayExponent(v) => {
                f.debug_tuple("AckDelayExponent").field(v).finish()
            }
            TransportParameter::MaxAckDelay(v) => f.debug_tuple("MaxAckDelay").field(v).finish(),
            TransportParameter::DisableActiveMigration(b) => {
                f.debug_tuple("DisableActiveMigration").field(b).finish()
            }
            TransportParameter::PreferredAddress(v) => f
                .debug_tuple("PreferredAddress")
                .field(&format_args!("{v:?}"))
                .finish(),
            TransportParameter::ActiveConnectionIdLimit(v) => {
                f.debug_tuple("ActiveConnectionIdLimit").field(v).finish()
            }
            TransportParameter::InitialSourceConnectionId(v) => f
                .debug_tuple("InitialSourceConnectionId")
                .field(&format_args!("{v:02x?}"))
                .finish(),
            TransportParameter::RetrySourceConnectionId(v) => f
                .debug_tuple("RetrySourceConnectionId")
                .field(&format_args!("{v:02x?}"))
                .finish(),
        }
    }
}

impl TransportParameter {
    fn type_id(&self) -> u64 {
        match self {
            TransportParameter::OriginalDestinationConnectionId(_) => {
                transport_param_type::ORIGINAL_DESTINATION_CONNECTION_ID
            }
            TransportParameter::MaxIdleTimeout(_) => transport_param_type::MAX_IDLE_TIMEOUT,
            TransportParameter::StatelessResetToken(_) => {
                transport_param_type::STATELESS_RESET_TOKEN
            }
            TransportParameter::MaxUdpPayloadSize(_) => transport_param_type::MAX_UDP_PAYLOAD_SIZE,
            TransportParameter::InitialMaxData(_) => transport_param_type::INITIAL_MAX_DATA,
            TransportParameter::InitialMaxStreamDataBidiLocal(_) => {
                transport_param_type::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            }
            TransportParameter::InitialMaxStreamDataBidiRemote(_) => {
                transport_param_type::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            }
            TransportParameter::InitialMaxStreamDataUni(_) => {
                transport_param_type::INITIAL_MAX_STREAM_DATA_UNI
            }
            TransportParameter::InitialMaxStreamsBidi(_) => {
                transport_param_type::INITIAL_MAX_STREAMS_BIDI
            }
            TransportParameter::InitialMaxStreamsUni(_) => {
                transport_param_type::INITIAL_MAX_STREAMS_UNI
            }
            TransportParameter::AckDelayExponent(_) => transport_param_type::ACK_DELAY_EXPONENT,
            TransportParameter::MaxAckDelay(_) => transport_param_type::MAX_ACK_DELAY,
            TransportParameter::DisableActiveMigration(_) => {
                transport_param_type::DISABLE_ACTIVE_MIGRATION
            }
            TransportParameter::PreferredAddress(_) => transport_param_type::PREFERRED_ADDRESS,
            TransportParameter::ActiveConnectionIdLimit(_) => {
                transport_param_type::ACTIVE_CONNECTION_ID_LIMIT
            }
            TransportParameter::InitialSourceConnectionId(_) => {
                transport_param_type::INITIAL_SOURCE_CONNECTION_ID
            }
            TransportParameter::RetrySourceConnectionId(_) => {
                transport_param_type::RETRY_SOURCE_CONNECTION_ID
            }
        }
    }

    pub(crate) fn deserialize(cursor: &mut Cursor<&[u8]>) -> Result<Option<TransportParameter>> {
        let type_id = decode_variable_length(cursor)?;
        trace!(
            "Deserializing transport parameter type 0x{:x} at position {}",
            type_id,
            cursor.position() - 1
        );

        let tp = match type_id {
            transport_param_type::ORIGINAL_DESTINATION_CONNECTION_ID => {
                let id_len = decode_variable_length(cursor)?;
                trace!(
                    "OriginalDestinationConnectionId length {} at position {}",
                    id_len,
                    cursor.position()
                );
                let mut org_dcid = vec![0; id_len as usize];
                cursor.read_exact(&mut org_dcid)?;
                trace!(
                    "Read OriginalDestinationConnectionId: {:02x?} at position {}",
                    org_dcid,
                    cursor.position()
                );
                TransportParameter::OriginalDestinationConnectionId(org_dcid)
            }
            transport_param_type::MAX_IDLE_TIMEOUT => {
                let timeout_len = decode_variable_length(cursor)?;
                trace!(
                    "MaxIdleTimeout length {} at position {}",
                    timeout_len,
                    cursor.position()
                );
                let timeout = decode_variable_length(cursor)?;
                trace!(
                    "MaxIdleTimeout value {} at position {}",
                    timeout,
                    cursor.position()
                );
                TransportParameter::MaxIdleTimeout(timeout)
            }
            transport_param_type::STATELESS_RESET_TOKEN => {
                let token_len = decode_variable_length(cursor)?;
                trace!(
                    "StatelessResetToken length {} at position {}",
                    token_len,
                    cursor.position()
                );
                let mut token = vec![0; token_len as usize];
                cursor.read_exact(&mut token)?;
                trace!(
                    "StatelessResetToken value {:02x?} at position {}",
                    token,
                    cursor.position()
                );
                TransportParameter::StatelessResetToken(token.try_into().unwrap())
            }
            transport_param_type::MAX_UDP_PAYLOAD_SIZE => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "MaxUdpPayloadSize length {} at position {}",
                    len,
                    cursor.position()
                );
                let size = decode_variable_length(cursor)? as u16;
                if !(MIN_UDP_PAYLOAD_SIZE..=MAX_UDP_PAYLOAD_SIZE).contains(&size) {
                    return Err(anyhow!(
                        "Invalid UDP payload size: {}, must be between {} and {}",
                        size,
                        MIN_UDP_PAYLOAD_SIZE,
                        MAX_UDP_PAYLOAD_SIZE
                    ));
                }
                trace!(
                    "MaxUdpPayloadSize value {} at position {}",
                    size,
                    cursor.position()
                );
                TransportParameter::MaxUdpPayloadSize(size)
            }
            transport_param_type::INITIAL_MAX_DATA => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxData length {} at position {}",
                    len,
                    cursor.position()
                );
                let max_data = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxData value {} at position {}",
                    max_data,
                    cursor.position()
                );
                TransportParameter::InitialMaxData(max_data)
            }
            transport_param_type::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataBidiLocal length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataBidiLocal value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamDataBidiLocal(value)
            }
            transport_param_type::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataBidiRemote length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataBidiRemote value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamDataBidiRemote(value)
            }
            transport_param_type::INITIAL_MAX_STREAM_DATA_UNI => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataUni length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamDataUni value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamDataUni(value)
            }
            transport_param_type::INITIAL_MAX_STREAMS_BIDI => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamsBidi length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamsBidi value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamsBidi(value)
            }
            transport_param_type::INITIAL_MAX_STREAMS_UNI => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamsUni length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                trace!(
                    "InitialMaxStreamsUni value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialMaxStreamsUni(value)
            }
            transport_param_type::ACK_DELAY_EXPONENT => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "AckDelayExponent length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                if value > 20 {
                    return Err(anyhow!(
                        "ack_delay_exponent value {} is not valid, must be 20 or below",
                        value
                    ));
                }
                trace!(
                    "AckDelayExponent value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::AckDelayExponent(value as u8)
            }
            transport_param_type::MAX_ACK_DELAY => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "MaxAckDelay length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                if value >= 1 << 14 {
                    return Err(anyhow!(
                        "max_ack_delay value {} is not valid, must be less than 2^14",
                        value
                    ));
                }
                trace!(
                    "MaxAckDelay value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::MaxAckDelay(value as u16)
            }
            transport_param_type::DISABLE_ACTIVE_MIGRATION => {
                let value = decode_variable_length(cursor)?;
                trace!(
                    "DisableActiveMigration value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::DisableActiveMigration(value == 0)
            }
            transport_param_type::ACTIVE_CONNECTION_ID_LIMIT => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "ActiveConnectionIdLimit length {} at position {}",
                    len,
                    cursor.position()
                );
                let value = decode_variable_length(cursor)?;
                if value < MIN_ACTIVE_CONNECTION_ID_LIMIT as u64 {
                    return Err(anyhow!(
                        "active_connection_id_limit must be at least {}, got {}",
                        MIN_ACTIVE_CONNECTION_ID_LIMIT,
                        value
                    ));
                }
                trace!(
                    "ActiveConnectionIdLimit value {} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::ActiveConnectionIdLimit(value as u8)
            }
            transport_param_type::INITIAL_SOURCE_CONNECTION_ID => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "InitialSourceConnectionId length {} at position {}",
                    len,
                    cursor.position()
                );
                let mut value = vec![0; len as usize];
                cursor.read_exact(&mut value)?;
                trace!(
                    "InitialSourceConnectionId value {:02x?} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::InitialSourceConnectionId(value)
            }
            transport_param_type::RETRY_SOURCE_CONNECTION_ID => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "RetrySourceConnectionId length {} at position {}",
                    len,
                    cursor.position()
                );
                let mut value = vec![0; len as usize];
                cursor.read_exact(&mut value)?;
                trace!(
                    "RetrySourceConnectionId value {:02x?} at position {}",
                    value,
                    cursor.position()
                );
                TransportParameter::RetrySourceConnectionId(value)
            }
            transport_param_type::PREFERRED_ADDRESS => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "PreferredAddress length {} at position {}",
                    len,
                    cursor.position()
                );

                // According to RFC 9000 Section 18.2, preferred address format:
                // IPv4 Address (32), IPv4 Port (16), IPv6 Address (128), IPv6 Port (16),
                // Connection ID Length (8), Connection ID (8..160), Stateless Reset Token (128)
                // Minimum length: 4 + 2 + 16 + 2 + 1 + 0 + 16 = 41 bytes
                if len < 41 {
                    return Err(anyhow!(
                        "Invalid preferred address length: expected at least 41 bytes, got {}",
                        len
                    ));
                }

                // Read IPv4 address (4 bytes)
                let mut ipv4_bytes = [0u8; 4];
                cursor.read_exact(&mut ipv4_bytes)?;
                let ipv4_address = Ipv4Addr::from(ipv4_bytes);

                // Read IPv4 port (2 bytes)
                let ipv4_port = cursor.read_u16::<BigEndian>()?;

                // Read IPv6 address (16 bytes)
                let mut ipv6_bytes = [0u8; 16];
                cursor.read_exact(&mut ipv6_bytes)?;
                let ipv6_address = Ipv6Addr::from(ipv6_bytes);

                // Read IPv6 port (2 bytes)
                let ipv6_port = cursor.read_u16::<BigEndian>()?;

                // Read connection ID length (1 byte)
                let connection_id_length = cursor.read_u8()?;

                // Validate connection ID length (RFC 9000: 0-20 bytes)
                if connection_id_length > 20 {
                    return Err(anyhow!(
                        "Invalid connection ID length in preferred address: {}",
                        connection_id_length
                    ));
                }

                // Read connection ID
                let mut connection_id = vec![0u8; connection_id_length as usize];
                cursor.read_exact(&mut connection_id)?;

                // Read stateless reset token (16 bytes)
                let mut stateless_reset_token = [0u8; 16];
                cursor.read_exact(&mut stateless_reset_token)?;

                trace!(
                    "PreferredAddress: IPv4={}:{}, IPv6=[{}]:{}, cid_len={}, cid={:02x?}, token={:02x?}",
                    ipv4_address, ipv4_port, ipv6_address, ipv6_port,
                    connection_id_length, connection_id, stateless_reset_token
                );

                TransportParameter::PreferredAddress(PreferredAddress {
                    ipv4_address,
                    ipv4_port,
                    ipv6_address,
                    ipv6_port,
                    connection_id_length,
                    connection_id,
                    stateless_reset_token,
                })
            }
            transport_param_type::GREASE_QUIC_BIT => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "GreaseQuicBit length {} at position {}",
                    len,
                    cursor.position()
                );
                // For grease_quic_bit, length should be 0
                if len != 0 {
                    warn!(
                        "grease_quic_bit parameter should have length 0, got {}",
                        len
                    );
                    let mut dummy = vec![0; len as usize];
                    cursor.read_exact(&mut dummy)?;
                }
                // Ignore GREASE parameters as per spec
                return Ok(None);
            }
            transport_param_type::GREASE => {
                let len = decode_variable_length(cursor)?;
                trace!(
                    "Grease parameter length {} at position {}",
                    len,
                    cursor.position()
                );
                // Skip the GREASE parameter value
                let mut dummy = vec![0; len as usize];
                cursor.read_exact(&mut dummy)?;
                trace!("Grease parameter value {:02x?}", dummy);
                // Ignore GREASE parameters as per spec
                return Ok(None);
            }
            _ => {
                // TODO: Could be version_infomation parameter
                // https://www.rfc-editor.org/info/rfc9368
                // or Ack frequency
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency
                let len = decode_variable_length(cursor)?;
                warn!(
                    "Invalid or unsupported transport parameter type id: 0x{:x}, len {}",
                    type_id, len,
                );
                let mut value = vec![0; len as usize];
                cursor.read_exact(&mut value)?;

                return Ok(None);
            }
        };

        trace!("Completed deserializing transport parameter {:?}", tp);
        Ok(Some(tp))
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-18
    pub(crate) fn serialize<W>(&self, cursor: &mut W) -> Result<()>
    where
        W: Write + Seek + Read,
    {
        // Write the type ID for this transport parameter
        encode_variable_length(cursor, self.type_id())?;

        match self {
            TransportParameter::OriginalDestinationConnectionId(id) => {
                encode_variable_length(cursor, id.len() as u64)?;
                cursor.write_all(id)?;
            }
            TransportParameter::MaxIdleTimeout(timeout) => {
                encode_variable_length(cursor, get_variable_length(*timeout)? as u64)?;
                encode_variable_length(cursor, *timeout)?;
            }
            TransportParameter::StatelessResetToken(token) => {
                encode_variable_length(cursor, token.len() as u64)?;
                cursor.write_all(token)?;
            }
            TransportParameter::MaxUdpPayloadSize(data) => {
                encode_variable_length(cursor, get_variable_length(*data as u64)? as u64)?;
                encode_variable_length(cursor, *data as u64)?;
            }
            TransportParameter::InitialMaxData(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamDataBidiLocal(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamDataBidiRemote(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamDataUni(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamsBidi(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::InitialMaxStreamsUni(data) => {
                encode_variable_length(cursor, get_variable_length(*data)? as u64)?;
                encode_variable_length(cursor, *data)?;
            }
            TransportParameter::AckDelayExponent(data) => {
                encode_variable_length(cursor, get_variable_length(*data as u64)? as u64)?;
                encode_variable_length(cursor, *data as u64)?;
            }
            TransportParameter::MaxAckDelay(data) => {
                encode_variable_length(cursor, get_variable_length(*data as u64)? as u64)?;
                encode_variable_length(cursor, *data as u64)?;
            }
            TransportParameter::DisableActiveMigration(_) => {
                encode_variable_length(cursor, 0)?;
            }
            TransportParameter::PreferredAddress(address) => {
                // Calculate the length: 4+2+16+2+1+cid_len+16 bytes
                let length = 4 + 2 + 16 + 2 + 1 + address.connection_id.len() + 16;
                encode_variable_length(cursor, length as u64)?;
                address.serialize(cursor)?;
            }
            TransportParameter::ActiveConnectionIdLimit(data) => {
                encode_variable_length(cursor, get_variable_length(*data as u64)? as u64)?;
                encode_variable_length(cursor, *data as u64)?;
            }
            TransportParameter::InitialSourceConnectionId(id) => {
                encode_variable_length(cursor, id.len() as u64)?;
                cursor.write_all(id)?;
            }
            TransportParameter::RetrySourceConnectionId(id) => {
                encode_variable_length(cursor, id.len() as u64)?;
                cursor.write_all(id)?;
            }
        }

        Ok(())
    }
}

impl PreferredAddress {
    fn serialize<W>(&self, cursor: &mut W) -> Result<()>
    where
        W: Write,
    {
        // Preferred Address {
        //   IPv4 Address (32),
        //   IPv4 Port (16),
        //   IPv6 Address (128),
        //   IPv6 Port (16),
        //   Connection ID Length (8),
        //   Connection ID (..),
        //   Stateless Reset Token (128),
        // }
        cursor.write_all(&self.ipv4_address.octets())?;
        cursor.write_u16::<BigEndian>(self.ipv4_port)?;
        cursor.write_all(&self.ipv6_address.octets())?;
        cursor.write_u16::<BigEndian>(self.ipv6_port)?;
        cursor.write_u8(self.connection_id_length)?;
        cursor.write_all(&self.connection_id)?;
        cursor.write_all(&self.stateless_reset_token)?;
        Ok(())
    }

    /// Get the IPv4 address
    pub(crate) fn get_ipv4_address(&self) -> Ipv4Addr {
        self.ipv4_address
    }

    /// Get the IPv4 port
    pub(crate) fn get_ipv4_port(&self) -> u16 {
        self.ipv4_port
    }

    /// Get the IPv6 address
    pub(crate) fn get_ipv6_address(&self) -> Ipv6Addr {
        self.ipv6_address
    }

    /// Get the IPv6 port
    pub(crate) fn get_ipv6_port(&self) -> u16 {
        self.ipv6_port
    }

    /// Get the connection ID
    pub(crate) fn get_connection_id(&self) -> &Vec<u8> {
        &self.connection_id
    }
}

pub(crate) fn search_transport_parameters<F>(
    tps: &[TransportParameter],
    condition: F,
) -> Option<&TransportParameter>
where
    F: Fn(&TransportParameter) -> bool,
{
    tps.iter().find(|&item| condition(item))
}

pub(crate) fn parse_server_transport_parameters(
    cursor: &mut Cursor<&[u8]>,
    length: u16,
) -> Result<Vec<TransportParameter>> {
    let mut tp = vec![];
    let tp_start_pos = cursor.position();
    trace!(
        "Start to parse server transport parameter, start pos {}, tp size {}",
        tp_start_pos,
        length
    );

    while cursor.position() - tp_start_pos < length as u64 {
        if let Some(t) = TransportParameter::deserialize(cursor)? {
            tp.push(t);
        }
    }

    if cursor.position() != tp_start_pos + (length as u64) {
        return Err(anyhow!(
            "Invalid server transport parameter length {} \
            , tp_start_pos: {}, cursor_pos: {}",
            length,
            tp_start_pos,
            cursor.position()
        ));
    }

    Ok(tp)
}

pub(crate) fn create_client_transport_parameters(
    quic_config: &QuicConfig,
    scid: &[u8],
) -> Vec<TransportParameter> {
    let mut parameters = vec![
        TransportParameter::MaxIdleTimeout(quic_config.get_idle_timeout()),
        TransportParameter::InitialMaxData(quic_config.get_initial_max_data()),
        TransportParameter::InitialSourceConnectionId(scid.to_vec()),
        TransportParameter::InitialMaxStreamDataBidiLocal(
            quic_config.get_initial_max_stream_data_bidi_local(),
        ),
        TransportParameter::InitialMaxStreamDataBidiRemote(
            quic_config.get_initial_max_stream_data_bidi_remote(),
        ),
        TransportParameter::InitialMaxStreamDataUni(quic_config.get_initial_max_stream_data_uni()),
        TransportParameter::InitialMaxStreamsBidi(quic_config.get_initial_max_streams_bidi()),
        TransportParameter::InitialMaxStreamsUni(quic_config.get_initial_max_streams_uni()),
        TransportParameter::AckDelayExponent(quic_config.get_ack_delay_exponent()),
        TransportParameter::MaxAckDelay(quic_config.get_max_ack_delay()),
        TransportParameter::DisableActiveMigration(quic_config.get_disable_active_migration()),
        TransportParameter::ActiveConnectionIdLimit(quic_config.get_active_connection_id_limit()),
    ];

    if let Some(max_udp_payload_size) = quic_config.get_max_udp_payload_size() {
        info!("Sending max UDP payload size: {}", max_udp_payload_size);
        parameters.push(TransportParameter::MaxUdpPayloadSize(max_udp_payload_size));
    }

    parameters
}

#[derive(Debug, Default)]
pub(crate) struct PeerTransportParameters {
    max_idle_timeout: Option<u64>,
    max_ack_delay: Option<u16>,
    ack_delay_exponent: Option<u8>,
    initial_max_data: Option<u64>,
    initial_max_stream_data_bidi_local: Option<u64>,
    initial_max_stream_data_bidi_remote: Option<u64>,
    initial_max_stream_data_uni: Option<u64>,
    initial_max_streams_bidi: Option<u64>,
    initial_max_streams_uni: Option<u64>,
    stateless_reset_token: Option<[u8; QUIC_STATELESS_RESET_TOKEN_SIZE as usize]>,
    max_udp_payload_size: Option<u16>,
    disable_active_migration: Option<bool>,
    preferred_address: Option<PreferredAddress>,
    active_connection_id_limit: Option<u8>,
    original_destination_connection_id: Option<Vec<u8>>,
    retry_source_connection_id: Option<Vec<u8>>,
    updated: bool,
}

impl PeerTransportParameters {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn update_from_tls(&mut self, tls: &TlsContext) {
        if self.updated {
            return;
        }
        self.max_idle_timeout = tls.get_peer_idle_timeout();
        self.max_ack_delay = tls.get_peer_max_ack_delay();
        self.ack_delay_exponent = tls.get_peer_ack_delay_exponent();
        self.initial_max_data = tls.get_peer_initial_max_data();
        self.initial_max_stream_data_bidi_local = tls.get_peer_initial_max_stream_data_bidi_local();
        self.initial_max_stream_data_bidi_remote =
            tls.get_peer_initial_max_stream_data_bidi_remote();
        self.initial_max_stream_data_uni = tls.get_peer_initial_max_stream_data_uni();
        self.initial_max_streams_bidi = tls.get_peer_initial_max_streams_bidi();
        self.initial_max_streams_uni = tls.get_peer_initial_max_streams_uni();
        self.stateless_reset_token = tls.get_peer_stateless_reset_token();
        self.max_udp_payload_size = tls.get_peer_max_udp_payload_size();
        // Migration related parameters
        self.disable_active_migration = tls.get_peer_disable_active_migration();
        self.preferred_address = tls.get_peer_preferred_address();
        self.active_connection_id_limit = tls.get_peer_active_connection_id_limit();
        self.original_destination_connection_id = tls.get_peer_original_destination_connection_id();
        self.retry_source_connection_id = tls.get_peer_retry_source_connection_id();
        self.updated = true;
    }

    pub(crate) fn get_max_udp_payload_size(&self) -> Option<u16> {
        self.max_udp_payload_size
    }

    pub(crate) fn get_max_idle_timeout(&self) -> Option<u64> {
        self.max_idle_timeout
    }

    pub(crate) fn get_max_ack_delay(&self) -> Option<u16> {
        self.max_ack_delay
    }

    pub(crate) fn get_ack_delay_exponent(&self) -> Option<u8> {
        self.ack_delay_exponent
    }

    pub(crate) fn get_initial_max_data(&self) -> Option<u64> {
        self.initial_max_data
    }

    pub(crate) fn get_initial_max_stream_data_bidi_local(&self) -> Option<u64> {
        self.initial_max_stream_data_bidi_local
    }

    pub(crate) fn get_initial_max_stream_data_bidi_remote(&self) -> Option<u64> {
        self.initial_max_stream_data_bidi_remote
    }

    pub(crate) fn get_initial_max_stream_data_uni(&self) -> Option<u64> {
        self.initial_max_stream_data_uni
    }

    pub(crate) fn get_initial_max_streams_bidi(&self) -> Option<u64> {
        self.initial_max_streams_bidi
    }

    pub(crate) fn get_initial_max_streams_uni(&self) -> Option<u64> {
        self.initial_max_streams_uni
    }

    pub(crate) fn get_stateless_reset_token(
        &self,
    ) -> Option<[u8; QUIC_STATELESS_RESET_TOKEN_SIZE as usize]> {
        self.stateless_reset_token
    }

    /// Get disable_active_migration parameter from peer
    /// Returns true if peer has disabled active migration
    pub(crate) fn get_disable_active_migration(&self) -> Option<bool> {
        self.disable_active_migration
    }

    /// Get preferred_address parameter from peer
    /// Contains IPv4/IPv6 addresses that peer prefers for connection migration
    pub(crate) fn get_preferred_address(&self) -> Option<&PreferredAddress> {
        self.preferred_address.as_ref()
    }

    /// Get active_connection_id_limit parameter from peer
    /// Limits the number of connection IDs that the peer is willing to store
    pub(crate) fn get_active_connection_id_limit(&self) -> Option<u8> {
        self.active_connection_id_limit
    }

    /// Get original_destination_connection_id parameter from peer
    /// This should match the original DCID used when establishing the connection
    pub(crate) fn get_original_destination_connection_id(&self) -> Option<&Vec<u8>> {
        self.original_destination_connection_id.as_ref()
    }

    /// Get retry_source_connection_id parameter from peer
    /// This should be present if a Retry packet was used during connection establishment
    pub(crate) fn get_retry_source_connection_id(&self) -> Option<&Vec<u8>> {
        self.retry_source_connection_id.as_ref()
    }
}
