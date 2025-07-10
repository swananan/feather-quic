use anyhow::{anyhow, Context, Result};
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{error, info, span, trace, warn, Level};

use crate::config::QuicConfig;
use crate::crypto::QuicCrypto;
use crate::error_code::{QuicConnectionErrorCode, TransportErrorCode};
use crate::flow_control::QuicConnectionFlowControl;
use crate::frame::{QuicFrame, QuicPing};
use crate::migration::QuicMigration;
use crate::mtu_discovery::{MtuDiscovery, MtuDiscoveryConfig};
use crate::packet::QuicPacket;
use crate::rtt::QuicRttGenerator;
use crate::runtime::QuicUserContext;
use crate::send::QuicSendContext;
use crate::stream::{QuicStream, QuicStreamError, QuicStreamHandle};
use crate::tls::TlsContext;
use crate::transport_parameters::{PeerTransportParameters, MIN_ACTIVE_CONNECTION_ID_LIMIT};
use crate::utils::{decode_variable_length, format_instant, remaining_bytes};
use crate::QuicCallbacks;

// https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3-11
const QUIC_RESET_PACKET_MIN_SIZE: u16 = 21;
pub(crate) const QUIC_STATELESS_RESET_TOKEN_SIZE: u16 = 16;
const QUIC_PATH_MAX_SIZE: usize = 100;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum QuicLevel {
    Initial,
    Handshake,
    Application,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QuicConnectionState {
    Init,
    Connecting,
    Established,
    ConnectionDraining,
    ConnectionClosing,
    ConnectionClosed,
}

#[derive(Error, Debug)]
pub enum QuicConnectResult {
    #[error("Connection established successfully")]
    Success,

    #[error("Connection establishment timed out {0}ms")]
    Timeout(u64),

    #[error("Connection establishment failed, due to {0}")]
    Failed(String),
}

#[derive(Error, Debug)]
pub enum QuicConnectionError {
    #[error("Stream {0} doesn't exist!")]
    StreamNotExist(QuicStreamHandle),

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-6
    #[error("Can not open {0} stream, current limitation is {1:?}!")]
    StreamLimitations(String, Option<u64>),

    #[error("Can not send any byte, current connection max data is {0}!")]
    ConnectionMaxDataLimitations(u64),

    #[error("Error from QUIC stream")]
    QuicStreamError(#[from] QuicStreamError),

    #[error("Internal implementation error {0}")]
    InternalError(String),

    #[error("Can not support for this operation, {0}")]
    ConnectionWrongState(String),

    #[error("QUIC Connection was closed {0:?}")]
    ConnectionLost(QuicConnectionState),
}

pub struct QuicConnection {
    pub(crate) quic_config: QuicConfig,
    state: QuicConnectionState,
    pub(crate) current_ts: Instant,
    pub(crate) idle_timeout: Option<u64>,
    idle_timeout_threshold: Option<Instant>,
    idle_close_trigger: bool,

    pub(crate) scid: Vec<u8>,
    pub(crate) crypto: QuicCrypto,
    pub(crate) tls: TlsContext,
    pub(crate) retry_token: Option<Vec<u8>>,
    pub(crate) retry_source_connection_id: Option<Vec<u8>>,
    pub(crate) new_token: Option<Vec<u8>>,

    pub(crate) key_phase: u8,
    discard_oldkey_threshold: Option<Instant>,
    detect_lost_threshold: Option<Instant>,
    pto_backoff: u16,
    pto_threshold: Option<Instant>,
    ack_delay_threshold: Option<Instant>,

    should_send_asap: bool,
    send_event_threshold: Option<Instant>,

    send_queue: VecDeque<(Vec<Vec<u8>>, SocketAddr)>, // UDP datagram with target address
    pub(crate) init_send: QuicSendContext,
    pub(crate) hs_send: QuicSendContext,
    pub(crate) app_send: QuicSendContext,

    pub(crate) rtt: QuicRttGenerator,

    connect_done_called: bool,
    peer_transport_params: PeerTransportParameters,

    close_called: bool,
    close_threshold: Option<Instant>,
    error_code: Option<QuicConnectionErrorCode>,
    peer_error_code: Option<QuicConnectionErrorCode>,
    reason_phrase: Option<String>,
    peer_reason_phrase: Option<String>,

    // QUIC Streams
    streams: HashMap<QuicStreamHandle, QuicStream>,
    next_bidi_local_stream_id: u64,
    next_uni_local_stream_id: u64,
    max_remote_stream_id: Option<u64>,
    flow_control: QuicConnectionFlowControl,

    pub(crate) mtu: MtuDiscovery,
    mtu_probe_size: Option<u16>,
    mtu_probe_timeout_threshold: Option<Instant>,

    // QUIC Path management for connection migration
    pub(crate) migration: QuicMigration,

    pub(crate) org_dcid: Vec<u8>,
    pub(crate) available_local_connection_ids: HashMap<u64, (Vec<u8>, [u8; 16])>,
    pub(crate) local_connection_ids_lookup: HashSet<Vec<u8>>,
    pub(crate) next_local_connection_id_sequence: u64,
    pub(crate) suggested_peer_retire_prior_to: u64,

    // Migration parameters from peer transport parameters
    peer_disable_active_migration: bool,
    peer_active_connection_id_limit: u8,
}

impl QuicConnection {
    pub fn new(mut quic_config: QuicConfig, target_address: SocketAddr) -> Self {
        const CID_LENGTH: usize = 16;
        let mut rng = rand::thread_rng();
        let scid = if quic_config.scid.is_none() {
            let mut tmp_scid: Vec<u8> = vec![];
            tmp_scid.resize_with(CID_LENGTH, || rng.gen_range(0..255));
            tmp_scid
        } else {
            quic_config.scid.take().unwrap()
        };

        let org_dcid = if quic_config.org_dcid.is_none() {
            let mut dcid: Vec<u8> = vec![];
            dcid.resize_with(CID_LENGTH, || rng.gen_range(0..255));
            dcid
        } else {
            quic_config.org_dcid.take().unwrap()
        };

        let mtu_config = MtuDiscoveryConfig::from_quic_config(&quic_config);

        info!(
            "[MTU] Initializing MTU discovery with timeout: {}ms, max retries: {}, network type: {:?}",
            mtu_config.probe_timeout_ms, mtu_config.max_probe_retries, mtu_config.network_type
        );

        let now = Instant::now();

        let mut scids = HashSet::new();
        scids.insert(scid.clone());

        // Initialize available_local_connection_ids with the initial scid (sequence 0)
        let mut available_local_connection_ids = HashMap::new();
        available_local_connection_ids.insert(0, (scid.clone(), [0; 16]));

        // Initialize lookup set for fast scid checking
        let mut local_connection_ids_lookup = HashSet::new();
        local_connection_ids_lookup.insert(scid.clone());

        // Initialize QUIC path management (do not insert path yet)
        let mut migration = QuicMigration::new(QUIC_PATH_MAX_SIZE);
        let handshake_path_id = migration
            .add_path(target_address, now)
            .expect("Failed to add handshake path");
        migration.set_active_path_id(handshake_path_id);

        QuicConnection {
            state: QuicConnectionState::Init,
            crypto: QuicCrypto::default(),
            tls: TlsContext::new(&quic_config, &scid),
            current_ts: now,
            idle_timeout_threshold: None,
            idle_close_trigger: false,
            scid,
            retry_token: None,
            retry_source_connection_id: None,
            new_token: None,
            idle_timeout: None,
            org_dcid,
            quic_config,

            key_phase: 0,
            discard_oldkey_threshold: None,
            detect_lost_threshold: None,
            pto_backoff: 0,
            pto_threshold: None,
            send_event_threshold: None,
            should_send_asap: false,
            ack_delay_threshold: None,

            send_queue: VecDeque::new(),
            init_send: QuicSendContext::new(QuicLevel::Initial),
            hs_send: QuicSendContext::new(QuicLevel::Handshake),
            app_send: QuicSendContext::new(QuicLevel::Application),

            rtt: QuicRttGenerator::default(),

            streams: HashMap::default(),
            next_bidi_local_stream_id: 0,
            next_uni_local_stream_id: 2,
            max_remote_stream_id: None,
            connect_done_called: false,

            close_called: false,
            close_threshold: None,
            error_code: None,
            peer_error_code: None,
            reason_phrase: None,
            peer_reason_phrase: None,

            peer_transport_params: PeerTransportParameters::new(),
            flow_control: QuicConnectionFlowControl::new(),

            mtu: MtuDiscovery::new(mtu_config),
            mtu_probe_size: None,
            mtu_probe_timeout_threshold: None,

            // QUIC Path management for connection migration
            migration,

            // Local connection ID management
            available_local_connection_ids,
            local_connection_ids_lookup,
            // Start from 1, sequence 0 is the initial scid
            next_local_connection_id_sequence: 1,
            suggested_peer_retire_prior_to: 0,

            // Migration parameters (will be updated from transport parameters)
            peer_disable_active_migration: false, // Default: migration allowed
            peer_active_connection_id_limit: MIN_ACTIVE_CONNECTION_ID_LIMIT, // Default value per RFC 9000
        }
    }

    pub(crate) fn is_established(&self) -> bool {
        self.state == QuicConnectionState::Established
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.state == QuicConnectionState::ConnectionClosing
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state == QuicConnectionState::ConnectionClosed
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.state == QuicConnectionState::ConnectionDraining
    }

    pub(crate) fn set_connected(&mut self) -> Result<()> {
        if self.state == QuicConnectionState::Established {
            return Ok(());
        }
        self.expected_state(QuicConnectionState::Connecting)?;
        self.state = QuicConnectionState::Established;

        self.migration.set_active_path_validated();

        // TODO: Consider starting MTU discovery during connection establishment
        self.start_mtu_discovery()?;

        // Generate and send initial local connection IDs to reach the configured limit
        // This is done after handshake completion to ensure all transport parameters are negotiated
        self.generate_and_send_initial_local_connection_ids()?;

        // Check for preferred address and initiate migration if available
        self.handle_preferred_address_migration()?;

        Ok(())
    }

    // TODO: Support custom timestamp callback
    pub(crate) fn update_current_time(&mut self) {
        self.current_ts = Instant::now();
    }

    pub(crate) fn run_timer(&mut self) -> Result<()> {
        let span = span!(
            Level::TRACE,
            "quic_timer",
            scid = ?self.scid.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(""),
            dcid = ?self.format_span_dcid()
        );
        let _enter = span.enter();
        trace!("Processing timers at {:?}", self.current_ts);

        let compare_ts = |current_ts: &Instant, threshold: &Instant| -> bool {
            if *current_ts == *threshold {
                return true;
            }
            match threshold.checked_duration_since(*current_ts) {
                Some(d) => d.as_millis() == 0,
                None => true,
            }
        };

        // The total length of time over which consecutive PTOs expire is limited by the idle timeout.
        if let Some(idle_timeout_threshold) = self.idle_timeout_threshold.as_ref() {
            if compare_ts(&self.current_ts, idle_timeout_threshold) {
                warn!(
                    "Should shut down QUIC connection, due to idle timeout, \
                    current_ts {:?}, idle_timeout_threshold {:?}",
                    self.current_ts, idle_timeout_threshold
                );
                self.idle_timeout_threshold = None;
                self.idle_close_trigger = true;

                // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1-1
                // Sliently close
                self.real_close_handler();
                return Ok(());
            }
        }

        if let Some(discard_oldkey_threshold) = self.discard_oldkey_threshold.as_ref() {
            if compare_ts(&self.current_ts, discard_oldkey_threshold) {
                info!(
                    "We need to discard last key here, {:?}",
                    discard_oldkey_threshold
                );
                self.discard_oldkey_threshold = None;
                self.crypto.discard_last_key();
            }
        }

        if let Some(mtu_threshold) = self.mtu_probe_timeout_threshold.as_ref() {
            if compare_ts(&self.current_ts, mtu_threshold) {
                self.mtu_handler()?;
            }
        }

        if let Some(detect_lost_threshold) = self.detect_lost_threshold.as_ref() {
            if compare_ts(&self.current_ts, detect_lost_threshold) {
                self.detect_lost()?;
                self.set_loss_or_pto_timer()?;
            }
        }

        if let Some(pto_threshold) = self.pto_threshold.as_ref() {
            if compare_ts(&self.current_ts, pto_threshold) {
                self.pto_handler()?;
                self.pto_backoff += 1;
                self.set_loss_or_pto_timer()?;
            }
        }

        let mut send_data = false;
        if let Some(ack_delay_threshold) = self.ack_delay_threshold.as_ref() {
            if compare_ts(&self.current_ts, ack_delay_threshold) {
                self.ack_delay_threshold = None;
                trace!("Hit the ack delay timer");
                send_data = true;
            }
        }

        if self.should_send_asap {
            self.should_send_asap = false;
            send_data = true;
        }

        if let Some(send_event) = self.send_event_threshold.as_ref() {
            if compare_ts(&self.current_ts, send_event) {
                self.send_event_threshold = None;
                trace!("Hit the send event timer");
                send_data = true;
            }
        }

        if send_data {
            QuicPacket::update_quic_send_queue(self)?;
        }

        // Clean up expired path challenges
        self.cleanup_expired_path_challenges();

        if self.is_draining() {
            info!("Only need to reply the QUIC connection close frame, since got connection close");
            self.real_close_handler();
            return Ok(());
        }

        if let Some(close_event) = self.close_threshold.as_ref() {
            if compare_ts(&self.current_ts, close_event) {
                self.close_threshold = None;
                self.real_close_handler();
            }
        }

        trace!("Leave processing timers");

        Ok(())
    }

    fn real_close_handler(&mut self) {
        if self.is_closed() {
            warn!(
                "Attempting to call this method multiple times, which may indicate \
            a potential issue in the connection state management"
            );
            return;
        }

        self.state = QuicConnectionState::ConnectionClosed;
        self.discard_keys_safely(QuicLevel::Application);
        self.discard_keys_safely(QuicLevel::Handshake);
        self.discard_keys_safely(QuicLevel::Initial);
        info!("Now our QUIC connection has been closed");
    }

    pub(crate) fn next_time(&self) -> Option<u64> {
        let _span =
            span!(Level::TRACE,             "calculating next timer",
                scid = ?self.scid.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(""),
                dcid = ?self.format_span_dcid()
            )
            .entered();

        // Helper closure to calculate duration until threshold
        let time_until = |name: &str, threshold: Option<Instant>| -> u64 {
            let duration = threshold
                .map(|t| {
                    t.checked_duration_since(self.current_ts)
                        .map_or(0, |dur| dur.as_micros() as u64)
                })
                .unwrap_or(u64::MAX);

            if duration < u64::MAX {
                trace!(
                    "{} timer will trigger in {}ns, current_ts {:?}, threshold {:?}",
                    name,
                    duration,
                    self.current_ts,
                    threshold
                );
            }
            duration
        };

        // Calculate all timer durations
        let idle_timeout = time_until("Idle timeout", self.idle_timeout_threshold);
        let key_update = time_until("Key update", self.discard_oldkey_threshold);
        let detect_lost = time_until("Loss detection", self.detect_lost_threshold);
        let mtu_discovery = time_until("MTU discovery", self.mtu_probe_timeout_threshold);
        let pto = time_until("PTO", self.pto_threshold);
        let ack_delay = time_until("ACK delay", self.ack_delay_threshold);
        let close = time_until("Close event", self.close_threshold);

        // Special handling for send threshold due to should_send_asap flag
        let send = if self.should_send_asap {
            trace!("Send timer will trigger immediately");
            0
        } else {
            time_until("Send", self.send_event_threshold)
        };

        // Find the earliest timer
        let timeout = idle_timeout
            .min(key_update)
            .min(send)
            .min(detect_lost)
            .min(pto)
            .min(ack_delay)
            .min(close)
            .min(mtu_discovery);

        // Log the result
        match timeout {
            0 => {
                trace!("Next timer will trigger immediately");
                None
            }
            t if t == u64::MAX => {
                trace!("No active timers");
                Some(t)
            }
            t => {
                info!("Next timer will trigger in {}ns", t);
                Some(t)
            }
        }
    }

    pub(crate) fn update_idle_timeout_threshold(&mut self) {
        let idle_timeout = self.get_idle_timeout();
        self.idle_timeout_threshold = if idle_timeout != 0 {
            trace!(
                "Update the idle timeout threshold to next {}ms",
                idle_timeout,
            );
            self.current_ts
                .checked_add(Duration::from_millis(idle_timeout))
        } else {
            None
        };
    }

    pub(crate) fn provide_data(&mut self, rcvbuf: &[u8], remote_addr: SocketAddr) -> Result<()> {
        let span = span!(
            Level::TRACE,
            "providing_data",
            scid = ?self.scid.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(""),
            dcid = ?self.format_span_dcid()
        );
        let _enter = span.enter();

        if self.is_closed() || self.is_draining() {
            trace!("No need to take care the incoming UDP datagram");
            return Ok(());
        }

        // TODO: Should check if remote address changes (migration/rebinding),
        // but feather-quic only supports client implementation for now, so this is not considered.
        // This situation is mostly a server-side concern.
        QuicPacket::handle_quic_packet(rcvbuf, self, &remote_addr).with_context(|| {
            format!(
                "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                self.scid,
                self.migration.get_current_dcid(),
                self.org_dcid
            )
        })?;

        Ok(())
    }

    pub(crate) fn consume_data(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        let span = span!(
            Level::TRACE,
            "consuming data",
            scid = ?self.scid.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(""),
            dcid = ?self.format_span_dcid()
        );
        let _enter = span.enter();

        if !self.send_queue.is_empty() {
            if let Err(e) = self.set_loss_or_pto_timer() {
                error!("Failed to set loss or pto timer during consuming send queue, due to {e}");
            }
        }

        if let Some((datagram_packets, target_address)) = self.send_queue.pop_front() {
            // Flatten the datagram packets into a single buffer
            let data: Vec<u8> = datagram_packets
                .into_iter()
                .flat_map(|packet| packet.into_iter())
                .collect();

            Some((data, target_address))
        } else {
            None
        }
    }

    pub fn connect(
        &mut self,
        max_udp_payload_size: Option<u16>,
    ) -> Result<(), QuicConnectionError> {
        let span = span!(
            Level::TRACE,
            "connecting",
            scid = ?self.scid.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(""),
        );
        let _enter = span.enter();

        self.expected_state(QuicConnectionState::Init)
            .with_context(|| {
                format!(
                    "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                    self.scid,
                    self.migration.get_current_dcid(),
                    self.org_dcid
                )
            })
            .map_err(|e| QuicConnectionError::ConnectionWrongState(format!("Due to {e}")))?;

        self.state = QuicConnectionState::Connecting;
        self.update_current_time();

        if let Some(max_udp_payload_size) = max_udp_payload_size {
            info!(
                "Setting max UDP payload size to {} during connection establishment",
                max_udp_payload_size
            );
            self.quic_config
                .set_max_udp_payload_size(max_udp_payload_size)
                .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;
        }

        QuicPacket::start_tls_handshake(self, false)
            .with_context(|| {
                format!(
                    "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                    self.scid,
                    self.migration.get_current_dcid(),
                    self.org_dcid
                )
            })
            .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;

        self.update_idle_timeout_threshold();

        Ok(())
    }

    pub(crate) fn send_transport_connection_close_frame(
        &mut self,
        levels: &[QuicLevel],
        error_code: u64,
        reason: Option<String>,
        frame_type: Option<u64>,
    ) {
        if self.is_closing() || self.is_draining() {
            warn!(
                "Should not send connection close frame, since we have \
                already close the QUIC connection"
            );
            return;
        }

        self.error_code = Some(QuicConnectionErrorCode::create_transport_error_code(
            error_code, frame_type,
        ));
        self.reason_phrase = reason;

        self.send_connection_close_frame(levels);
    }

    pub(crate) fn send_connection_close_frame(&mut self, levels: &[QuicLevel]) {
        trace!("Send connection close frame on the levels {:?}", levels);

        let cc_frame = match self.error_code {
            Some(error_code) => {
                QuicFrame::create_connection_close_frame(error_code, self.reason_phrase.clone())
            }
            None => {
                panic!("Must have error_code here");
            }
        };

        self.set_next_send_event_time(0);

        for level in levels {
            let send_ctx = match level {
                QuicLevel::Initial => &mut self.init_send,
                QuicLevel::Handshake => &mut self.hs_send,
                QuicLevel::Application => &mut self.app_send,
            };
            send_ctx.insert_send_queue_back(cc_frame.clone());
        }
    }

    // Unit is millisecond
    pub(crate) fn three_times_pto(&self) -> u64 {
        3 * self.rtt.get_pto(QuicLevel::Application).as_millis() as u64 * (1 << self.pto_backoff)
    }

    pub(crate) fn close_helper(&mut self) {
        if self.is_closing() || self.is_draining() || self.is_closed() {
            return;
        }
        // Intention of calling close doesn't trigger the close callback
        self.close_called = true;
        self.state = QuicConnectionState::ConnectionClosing;
        self.close_threshold = self
            .current_ts
            .checked_add(Duration::from_millis(self.three_times_pto()));
    }

    pub(crate) fn close_internal(
        &mut self,
        error_code: u64,
        reason_phrase: Option<String>,
    ) -> Result<(), QuicConnectionError> {
        let span = span!(Level::TRACE, "trying close the QUIC connection",);
        let _enter = span.enter();

        self.expected_states(vec![
            QuicConnectionState::Connecting,
            QuicConnectionState::Established,
        ])
        .with_context(|| {
            format!(
                "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                self.scid,
                self.migration.get_current_dcid(),
                self.org_dcid
            )
        })
        .map_err(|e| QuicConnectionError::ConnectionWrongState(format!("Due to {e}")))?;

        self.error_code = Some(QuicConnectionErrorCode::create_application_error_code(
            error_code,
        ));
        self.reason_phrase = reason_phrase;

        if self.is_established() {
            self.send_connection_close_frame(&[QuicLevel::Application]);
        } else {
            self.send_connection_close_frame(&[QuicLevel::Initial, QuicLevel::Handshake]);
        }

        self.close_helper();

        info!(
            "Close event will be triggered at {}",
            format_instant(self.close_threshold.unwrap(), self.current_ts)
        );

        Ok(())
    }

    pub(crate) fn open_stream_internal(
        &mut self,
        is_bidirectional: bool,
    ) -> Result<QuicStreamHandle, QuicConnectionError> {
        let span = span!(
            Level::TRACE,
            "opening stream",
            bidirectional = is_bidirectional
        );
        let _enter = span.enter();

        if is_bidirectional
            && self
                .flow_control
                .get_max_streams_bidi_remote()
                .map(|max| self.flow_control.get_bi_stream_local_cnt() >= max)
                .unwrap_or(true)
        {
            self.create_and_insert_streams_blocked_stream(
                true,
                self.flow_control.get_max_streams_bidi_remote().unwrap_or(0),
            )
            .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;
            return Err(QuicConnectionError::StreamLimitations(
                "Bidirectional".to_string(),
                self.flow_control.get_max_streams_bidi_remote(),
            ));
        }

        if !is_bidirectional
            && self
                .flow_control
                .get_max_streams_uni_remote()
                .map(|max| self.flow_control.get_uni_stream_local_cnt() >= max)
                .unwrap_or(true)
        {
            self.create_and_insert_streams_blocked_stream(
                false,
                self.flow_control.get_max_streams_uni_remote().unwrap_or(0),
            )
            .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;

            return Err(QuicConnectionError::StreamLimitations(
                "Unidirectional".to_string(),
                self.flow_control.get_max_streams_uni_remote(),
            ));
        }

        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!(
                "Connection is in {:?}, so we can't open a new stream",
                self.state
            );
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        let new_id = if is_bidirectional {
            self.get_next_bi_local_stream_id()
        } else {
            self.get_next_uni_stream_id()
        };

        let max_send_size = if is_bidirectional {
            self.get_peer_initial_max_stream_data_bidi_remote()
                .unwrap_or(0)
        } else {
            self.get_peer_initial_max_stream_data_uni().unwrap_or(0)
        };

        let max_recv_size = if is_bidirectional {
            self.quic_config.get_initial_max_stream_data_bidi_local()
        } else {
            0
        };

        info!(
            "Opening new stream {:?} (directional: {}, max_send_size: {}, \
            max_recv_size: {})",
            new_id, is_bidirectional, max_send_size, max_recv_size
        );

        // Only supports QUIC client role
        let new_stream = QuicStream::new(new_id, max_send_size, max_recv_size);

        match self.streams.entry(new_id) {
            std::collections::hash_map::Entry::Occupied(e) => {
                panic!("Stream {e:?} already exists");
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(new_stream);
                if is_bidirectional {
                    self.flow_control.increment_bi_stream_local();
                } else {
                    self.flow_control.increment_uni_stream_local();
                }
                trace!("Successfully created new stream {:?}", new_id);
            }
        };

        Ok(new_id)
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1-7
    fn get_next_bi_local_stream_id(&mut self) -> QuicStreamHandle {
        let stream_id = self.next_bidi_local_stream_id;
        self.next_bidi_local_stream_id += 4;
        QuicStreamHandle::new(stream_id)
    }

    fn get_next_uni_stream_id(&mut self) -> QuicStreamHandle {
        let stream_id = self.next_uni_local_stream_id;
        self.next_uni_local_stream_id += 4;
        QuicStreamHandle::new(stream_id)
    }

    /// Only stop the sending for specific stream, ensure all the stream data be delivered in the
    /// peer side
    pub(crate) fn stream_finish_internal(
        &mut self,
        stream_handle: QuicStreamHandle,
    ) -> Result<(), QuicConnectionError> {
        let span = span!(Level::TRACE, "finishing stream", stream = ?stream_handle);
        let _enter = span.enter();

        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!(
                "Connection is in {:?}, so we can't finish the stream",
                self.state
            );
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        let stream = self.streams.get_mut(&stream_handle).ok_or_else(|| {
            error!("Stream {:?} not found when trying to finish", stream_handle);
            QuicConnectionError::StreamNotExist(stream_handle)
        })?;

        info!("Finishing stream {:?}", stream_handle);
        Ok(stream.finish()?)
    }

    /// Reset the QUIC stream sending immediately
    pub(crate) fn stream_shutdown_write_internal(
        &mut self,
        stream_handle: QuicStreamHandle,
        application_error_code: u64,
    ) -> Result<(), QuicConnectionError> {
        let span = span!(Level::TRACE, "shutting down stream write",
            stream = ?stream_handle,
            error_code = application_error_code
        );
        let _enter = span.enter();

        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!(
                "Connection is in {:?}, so we can't shutdown write",
                self.state
            );
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        let stream = self.streams.get_mut(&stream_handle).ok_or_else(|| {
            error!(
                "Stream {:?} not found when trying to shutdown write",
                stream_handle
            );
            QuicConnectionError::StreamNotExist(stream_handle)
        })?;

        info!(
            "Shutting down write for stream {:?} with error code {}",
            stream_handle, application_error_code
        );
        let reset_frame = stream.reset(application_error_code)?;
        self.app_send.insert_send_queue_back(reset_frame);
        self.set_next_send_event_time(0);

        // Shall we discard the all related stream frames in the send queue?
        // Yes
        // A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for a stream
        // in the "Reset Sent" state or any terminal state
        // -- that is, after sending a RESET_STREAM frame.

        Ok(())
    }

    /// Reset the QUIC stream receiving immediately
    pub(crate) fn stream_shutdown_read_internal(
        &mut self,
        stream_handle: QuicStreamHandle,
        application_error_code: u64,
    ) -> Result<(), QuicConnectionError> {
        let span = span!(Level::TRACE, "shutting down stream read",
            stream = ?stream_handle,
            error_code = application_error_code
        );
        let _enter = span.enter();

        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!(
                "Connection is in {:?}, so we can't shutdown read",
                self.state
            );
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        let stream = self.streams.get_mut(&stream_handle).ok_or_else(|| {
            error!(
                "Stream {:?} not found when trying to shutdown read",
                stream_handle
            );
            QuicConnectionError::StreamNotExist(stream_handle)
        })?;

        info!(
            "Shutting down read for stream {:?} with error code {}",
            stream_handle, application_error_code
        );
        let frame = stream.stop_sending(application_error_code)?;
        self.app_send.insert_send_queue_back(frame);
        self.set_next_send_event_time(0);

        Ok(())
    }

    pub(crate) fn stream_recv_internal(
        &mut self,
        stream_handle: QuicStreamHandle,
        recv_len: usize,
    ) -> Result<Vec<u8>, QuicConnectionError> {
        let span = span!(Level::TRACE, "receiving from stream",
            stream = ?stream_handle,
            length = recv_len
        );
        let _enter = span.enter();

        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!("Connection is in {:?}, so we can't receive", self.state);
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        let stream = self.streams.get_mut(&stream_handle).ok_or_else(|| {
            error!(
                "Stream {:?} not found when trying to receive",
                stream_handle
            );
            QuicConnectionError::StreamNotExist(stream_handle)
        })?;

        trace!(
            "Attempting to receive {} bytes from stream {:?}",
            recv_len,
            stream_handle
        );
        let result = stream.recv(recv_len)?;
        self.flow_control.increment_recv_offset(result.len() as u64);
        trace!(
            "Successfully received {} bytes from stream {:?}",
            result.len(),
            stream_handle
        );

        if !result.is_empty() {
            let res = stream.check_if_update_max_recv_data(false);
            let stream_max_size = stream.get_new_max_recv_size();
            let should_clean = stream.should_clean_stream();
            if res {
                self.create_and_insert_max_data_stream(Some(stream_handle), stream_max_size)
                    .map_err(|e| {
                        QuicConnectionError::InternalError(format!(
                            "Stream {stream_handle} failure, due to {e}"
                        ))
                    })?;
            }

            if should_clean {
                self.clean_stream(stream_handle);
            }

            if self.flow_control.check_if_update_max_recv_data(false) {
                self.create_and_insert_max_data_stream(
                    None,
                    self.flow_control.get_new_max_recv_size(),
                )
                .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;
            }
        }

        Ok(result)
    }

    fn clean_stream(&mut self, stream_handle: QuicStreamHandle) {
        // Clean stream doesn't mean that we need to decrease the stream count
        info!("Cleaning stream {}", stream_handle);
        self.streams.remove(&stream_handle);
        self.app_send
            .clear_stream_frame_from_sent_queue(stream_handle.as_u64());
    }

    pub(crate) fn stream_send_internal(
        &mut self,
        stream_handle: QuicStreamHandle,
        snd_buf: &[u8],
    ) -> Result<usize, QuicConnectionError> {
        let span = span!(Level::TRACE, "sending to stream",
            stream = ?stream_handle,
            length = snd_buf.len()
        );
        let _enter = span.enter();

        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!("Connection is in {:?}, so we can't send", self.state);
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        let stream = self.streams.get_mut(&stream_handle).ok_or_else(|| {
            error!("Stream {:?} not found when trying to send", stream_handle);
            QuicConnectionError::StreamNotExist(stream_handle)
        })?;

        if snd_buf.is_empty() {
            return Ok(0);
        }

        let available_bytes = self
            .flow_control
            .get_sent_available_bytes()
            .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;

        if available_bytes == 0 {
            // Actually QUIC stream frame length can be zero, but we provide the `finish` api
            warn!("Connection flow control was triggered here");
            let max_send_size = self.flow_control.get_max_send_size();
            self.create_and_insert_data_blocked_stream(None, max_send_size)
                .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;

            return Err(QuicConnectionError::ConnectionMaxDataLimitations(
                self.flow_control.get_max_send_size(),
            ));
        }

        let snd_len = if (available_bytes as usize) < snd_buf.len() {
            available_bytes as usize
        } else {
            snd_buf.len()
        };
        trace!(
            "Attempting to send {} bytes to stream {:?}, actually can send {} bytes",
            snd_buf.len(),
            stream_handle,
            snd_len,
        );

        let max_send_size = stream.get_max_send_size();
        match stream.send(&snd_buf[..snd_len]) {
            Ok(sent_bytes) => {
                self.flow_control.increment_sent_offset(sent_bytes as u64);
                trace!(
                    "Successfully sent {} bytes to stream {:?}",
                    sent_bytes,
                    stream_handle
                );

                Ok(sent_bytes)
            }
            Err(e) => {
                if matches!(e, QuicStreamError::WouldBlock) {
                    self.create_and_insert_data_blocked_stream(Some(stream_handle), max_send_size)
                        .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;
                }
                Err(QuicConnectionError::QuicStreamError(e))
            }
        }
    }

    pub(crate) fn set_stream_write_active_internal(
        &mut self,
        stream_handle: QuicStreamHandle,
        flag: bool,
    ) -> Result<(), QuicConnectionError> {
        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!(
                "Connection is in {:?}, so we can't set write active",
                self.state
            );
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        match self.streams.entry(stream_handle) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().set_write_active(flag);
                trace!("Set write active={} for stream {:?}", flag, stream_handle);
            }
            std::collections::hash_map::Entry::Vacant(_) => {
                error!(
                    "Stream {:?} not found when setting write active",
                    stream_handle
                );
                return Err(QuicConnectionError::StreamNotExist(stream_handle));
            }
        };
        Ok(())
    }

    pub(crate) fn set_stream_read_active_internal(
        &mut self,
        stream_handle: QuicStreamHandle,
        flag: bool,
    ) -> Result<(), QuicConnectionError> {
        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!(
                "Connection is in {:?}, so we can't set read active",
                self.state
            );
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        match self.streams.entry(stream_handle) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().set_read_active(flag);
                trace!("Set read active={} for stream {:?}", flag, stream_handle);
            }
            std::collections::hash_map::Entry::Vacant(_) => {
                error!(
                    "Stream {:?} not found when setting read active",
                    stream_handle
                );
                return Err(QuicConnectionError::StreamNotExist(stream_handle));
            }
        };
        Ok(())
    }

    /// Migrate the connection to a new target address
    ///
    /// This is a client-only API that allows the client to actively migrate
    /// the connection to a different server address. The migration process
    /// involves adding the new address as a potential path and sending
    /// PATH_CHALLENGE frames to validate it.
    ///
    /// # Arguments
    /// * `new_target_address` - The new target server address to migrate to
    ///
    /// # Returns
    /// * `Result<(), QuicConnectionError>` - Success or error
    pub(crate) fn migrate_to_address_internal(
        &mut self,
        new_target_address: SocketAddr,
    ) -> Result<(), QuicConnectionError> {
        let span = span!(
            Level::TRACE,
            "migrating to address",
            new_address = ?new_target_address
        );
        let _enter = span.enter();

        // Only one migration can be in progress at a time
        if self.migration.has_validating_path() {
            // TODO: Support multiple concurrent migrations in the future
            return Err(QuicConnectionError::ConnectionWrongState(
                "Migration already in progress".to_string(),
            ));
        }

        if self.is_closed() || self.is_closing() || self.is_draining() {
            info!("Connection is in {:?}, so we can't migrate", self.state);
            return Err(QuicConnectionError::ConnectionLost(self.state));
        }

        if !self.is_established() {
            info!("Connection is not established, cannot migrate");
            return Err(QuicConnectionError::ConnectionWrongState(
                "Connection must be established to migrate".to_string(),
            ));
        }

        if self.is_peer_migration_disabled() {
            info!("Peer has disabled active migration");
            return Err(QuicConnectionError::ConnectionWrongState(
                "Peer has disabled active migration".to_string(),
            ));
        }

        if self.quic_config.get_disable_active_migration() {
            info!("Active migration is disabled by configuration");
            return Err(QuicConnectionError::ConnectionWrongState(
                "Active migration is disabled by configuration".to_string(),
            ));
        }

        // Add the new path to the migration system (will auto-assign CID if available)
        match self.migration.add_path(new_target_address, self.current_ts) {
            Ok(path_id) => {
                info!(
                    "Added new migration path: path_id={}, address={:?}",
                    path_id, new_target_address
                );

                // Send PATH_CHALLENGE to validate the new path
                self.create_and_send_path_challenge_for_path(path_id)
                    .map_err(|e| {
                        QuicConnectionError::InternalError(format!(
                            "Failed to send path challenge: {e}"
                        ))
                    })?;

                info!(
                    "Migration to {:?} initiated successfully",
                    new_target_address
                );
                Ok(())
            }
            Err(e) => {
                error!("Failed to add migration path: {e}");
                Err(QuicConnectionError::InternalError(format!(
                    "Failed to add migration path: {e}"
                )))
            }
        }
    }

    pub(crate) fn check_peer_dcid(&self, dcid: &[u8]) -> bool {
        self.local_connection_ids_lookup.contains(dcid)
    }

    fn draining(&mut self, level: QuicLevel, reply_cc: bool) {
        if self.is_draining() {
            return;
        }

        info!(
            "Entering draining state, level {:?}, reply_cc {}",
            level, reply_cc
        );

        // Stop sending any packet and notify the application layer
        self.app_send.clear();
        self.hs_send.clear();
        self.init_send.clear();
        self.send_queue.clear();

        if reply_cc {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2-2
            TransportErrorCode::send_no_error_cc_frame(self, level, None);
        } else {
            // Trigger close event immediately
            self.close_threshold = Some(self.current_ts);
        }

        self.state = QuicConnectionState::ConnectionDraining;
    }

    pub(crate) fn handle_stateless_reset(&mut self, rcv_buf: &[u8]) {
        if rcv_buf.len() < QUIC_RESET_PACKET_MIN_SIZE as usize {
            return;
        }

        let reset_token = &rcv_buf[(rcv_buf.len() - QUIC_STATELESS_RESET_TOKEN_SIZE as usize)..];
        trace!(
            "Processing potential stateless reset packet, tokens: {:x?}",
            reset_token
        );

        // Check if the reset token matches any of our peer connection IDs
        let mut reset_token_array = [0u8; 16];
        if reset_token.len() == 16 {
            reset_token_array.copy_from_slice(reset_token);

            let available_cids = self.migration.get_all_peer_connection_ids();
            if available_cids
                .values()
                .any(|(_, token)| token == &reset_token_array)
            {
                self.peer_error_code = None;
                self.peer_reason_phrase = Some("quic stateless reset packet detected".to_string());
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.1-5
                // the endpoint MUST enter the draining period and not send any further packets on this connection
                self.draining(QuicLevel::Application, false);
            }
        }
    }

    pub(crate) fn handle_new_conncetion_id_frame(
        &mut self,
        sequence_number: u64,
        retire_prior_to: u64,
        new_scid: &[u8],
        reset_token: &[u8],
    ) -> Result<()> {
        if reset_token.len() as u16 != QUIC_STATELESS_RESET_TOKEN_SIZE {
            error!("Invalid reset token length: {}", reset_token.len());
            return Ok(());
        }

        info!(
            "Stored new peer connection ID: seq={}, retire_prior_to={}, cid={:x?}, token={:x?}",
            sequence_number, retire_prior_to, new_scid, reset_token
        );

        // Update max_peer_retire_prior_to and handle retirement of peer connection IDs
        self.migration
            .update_max_peer_retire_prior_to(retire_prior_to);

        if retire_prior_to > 0 {
            self.migration
                .retire_peer_connection_ids_before(retire_prior_to);
        }

        // Check if this peer connection ID sequence number has already been retired
        if self
            .migration
            .is_peer_connection_id_retired(sequence_number)
        {
            info!(
                "Ignoring NEW_CONNECTION_ID for already retired peer sequence {}: \
                cid={:x?} (max_peer_retire_prior_to={})",
                sequence_number,
                new_scid,
                self.migration.get_active_connection_id_sequence()
            );
            return Ok(());
        }

        // Check if this sequence number already exists in available connection IDs
        let available_cids = self.migration.get_all_peer_connection_ids();
        if available_cids.contains_key(&sequence_number) {
            info!(
                "Connection ID {:x?} already exists, dropping new connection ID {:x?}",
                available_cids.get(&sequence_number).unwrap().0,
                new_scid
            );
            if available_cids.get(&sequence_number).unwrap().0 != new_scid {
                error!(
                    "Current connection ID {:x?} is different from the new connection ID {:x?}",
                    available_cids.get(&sequence_number).unwrap().0,
                    new_scid
                );
            }
            return Ok(());
        }

        if self.migration.get_available_peer_connection_id_count()
            > self.get_local_connection_id_limit() as usize
        {
            error!(
                "Peer connection ID limit exceeded: {}, current: {}",
                self.get_local_connection_id_limit(),
                self.migration.get_available_peer_connection_id_count()
            );
            return Err(anyhow::Error::from(
                crate::error_code::QuicConnectionErrorCode::create_connection_id_limit_error(),
            ));
        }

        let mut reset_token_array = [0u8; 16];
        reset_token_array.copy_from_slice(reset_token);

        // Store the new connection ID with its sequence number from the frame
        self.migration.add_peer_connection_id(
            sequence_number,
            new_scid.to_vec(),
            reset_token_array,
        )?;

        Ok(())
    }

    pub(crate) fn handle_path_challenge_frame(&mut self, data: [u8; 8]) -> Result<()> {
        trace!("Got PATH_CHALLENGE frame: data={:x?}", data);

        // Send PATH_RESPONSE frame immediately
        let response_frame = QuicFrame::create_path_response_frame(data);
        self.app_send.insert_send_queue_front(response_frame);
        self.set_next_send_event_time(0);

        // Consider triggering MTU discovery if conditions are met
        self.reset_mtu();
        self.start_mtu_discovery()?;

        trace!("PATH_CHALLENGE handled, PATH_RESPONSE queued for immediate send");
        Ok(())
    }

    pub(crate) fn handle_path_response_frame(&mut self, data: [u8; 8]) -> Result<()> {
        trace!("Got PATH_RESPONSE frame: data={:x?}", data);

        // Use the migration system to handle the response and get the validated path ID
        if let Some(validated_path_id) = self.migration.handle_path_response(data)? {
            info!(
                "Path validation completed successfully for path: {}",
                validated_path_id
            );

            // Check if the validated path is different from the current active path
            if let Some(current_active_path) = self.migration.get_active_path() {
                if current_active_path.path_id != validated_path_id {
                    // Switch to the newly validated path and get the old path ID
                    match self.migration.switch_to_path(validated_path_id, true) {
                        Ok(old_path_id) => {
                            info!(
                                "Successfully switched to newly validated path: {} (from path: {})",
                                validated_path_id, old_path_id
                            );

                            // Reset and restart MTU discovery on migration
                            self.reset_mtu();
                            self.start_mtu_discovery()?;

                            // Set migration result pending in migration
                            let is_preferred = validated_path_id == 1
                                && self.get_peer_preferred_address().is_some();
                            if is_preferred {
                                self.migration.set_migration_result_pending(
                                    old_path_id,
                                    validated_path_id,
                                    crate::migration::MigrationResult::MigrationPreferredAddressSuccess,
                                );
                            } else {
                                self.migration.set_migration_result_pending(
                                    old_path_id,
                                    validated_path_id,
                                    crate::migration::MigrationResult::MigrationSuccess,
                                );
                            }
                            // Send RETIRE_CONNECTION_ID frame for the old path's connection ID
                            if let Some(old_sequence) =
                                self.migration.get_path_connection_id_sequence(old_path_id)
                            {
                                self.send_retire_connection_id_frame(old_sequence)?;
                            } else {
                                error!(
                                    "No connection ID sequence found for old path {}",
                                    old_path_id
                                );
                            }

                            self.migration.set_path_retired(old_path_id);
                            self.cleanup_expired_path_challenges();
                        }
                        Err(e) => {
                            error!(
                                "Error switching to validated path {}: {}",
                                validated_path_id, e
                            );
                        }
                    }
                } else {
                    info!(
                        "Validated path {} is already the active path",
                        validated_path_id
                    );
                }
            } else {
                error!(
                    "No active path found, cannot switch to validated path {}",
                    validated_path_id
                );
            }
        } else {
            warn!(
                "Received PATH_RESPONSE for unknown challenge: data={:x?}",
                data
            );
        }

        Ok(())
    }

    pub(crate) fn handle_retire_connection_id_frame(&mut self, sequence_number: u64) -> Result<()> {
        info!(
            "Handling RETIRE_CONNECTION_ID frame: sequence_number={}",
            sequence_number
        );

        // This frame is asking us to retire one of OUR connection IDs that we gave to the peer
        if let Some((retired_cid, _)) = self.available_local_connection_ids.remove(&sequence_number)
        {
            // Also remove from lookup set
            self.local_connection_ids_lookup.remove(&retired_cid);
            info!(
                "Peer requested retirement of our local connection ID: sequence={}, cid={:x?}",
                sequence_number, retired_cid
            );

            // Calculate a suitable retire_prior_to value to suggest peer retirement
            // We should suggest retiring peer connection IDs that are older but not including
            // any currently active connection IDs
            let suggested_retire_prior_to = self.calculate_suggested_peer_retire_prior_to();

            // Try to generate a new connection ID to maintain the limit
            // If we have a retirement suggestion, use it; otherwise use None to keep current behavior
            if suggested_retire_prior_to > self.suggested_peer_retire_prior_to {
                self.suggested_peer_retire_prior_to = suggested_retire_prior_to;
                self.generate_new_local_connection_id_with_retire_prior_to(Some(
                    suggested_retire_prior_to,
                ))?;
                info!(
                    "Suggesting peer retire connection IDs with sequence < {} when sending new connection ID",
                    suggested_retire_prior_to
                );
            } else {
                self.maybe_generate_new_local_connection_id()?;
            }
        } else {
            warn!(
                "Peer requested retirement of unknown local connection ID: sequence={}",
                sequence_number
            );
        }

        Ok(())
    }

    pub(crate) fn create_and_send_path_challenge_for_path(&mut self, path_id: u64) -> Result<()> {
        let challenge_data = rand::random::<[u8; 8]>();

        // Integration with migration system for path validation tracking
        if let Some(path) = self.migration.get_path_mut(path_id) {
            let active_path_id = path.path_id;

            // If the active path is not currently being validated, start validation
            if !path.is_validating() {
                path.start_validation(challenge_data, self.current_ts);
                info!(
                    "Started path validation for active path {}: challenge_data={:x?}",
                    active_path_id, challenge_data
                );
            } else {
                // Path is already being validated, but we can still send a challenge
                warn!("Active path {} is already being validated, sending additional challenge: data={:x?}", 
                      active_path_id, challenge_data);
            }
        } else {
            error!("No {path_id} path found for PATH_CHALLENGE, sending generic challenge");
        }

        let challenge_frame = QuicFrame::create_path_challenge_frame(challenge_data);

        self.app_send.insert_send_queue_front(challenge_frame);

        let tmp_active_path_id = self.migration.switch_to_path(path_id, false)?;

        // Immediately create and send QUIC packet (following standard pattern)
        let datagram_buf = QuicPacket::create_quic_packet(self, QuicLevel::Application, 1)?
            .ok_or_else(|| {
                anyhow!("Must create the QUIC packet successfully for PATH_CHALLENGE")
            })?;
        self.update_packet_send_queue(vec![datagram_buf]);
        self.set_next_send_event_time(0);
        self.migration.switch_to_path(tmp_active_path_id, false)?;

        info!(
            "Created and sent PATH_CHALLENGE frame: data={:x?}, path_id={}",
            challenge_data, path_id
        );

        Ok(())
    }

    fn cleanup_expired_path_challenges(&mut self) {
        let retry_paths = self.migration.check_validation_timeouts(self.current_ts);
        for path_id in retry_paths {
            if let Err(e) = self.create_and_send_path_challenge_for_path(path_id) {
                error!("Failed to send path challenge for path {}: {}", path_id, e);
            }
        }
    }

    /// Handle preferred address migration after handshake completion
    ///
    /// According to RFC 9000 Section 9.5, when a server provides a preferred address,
    /// the client SHOULD migrate to that address after the handshake completes.
    fn handle_preferred_address_migration(&mut self) -> Result<()> {
        if self.quic_config.get_disable_active_migration() {
            warn!("Active migration is disabled, skipping preferred address migration");
            return Ok(());
        }

        // Check if peer has provided a preferred address
        if let Some(preferred_addr) = self.get_peer_preferred_address() {
            info!(
                "Peer provided preferred address: IPv4={}:{}, IPv6=[{}]:{}, connection_id={:x?}",
                preferred_addr.get_ipv4_address(),
                preferred_addr.get_ipv4_port(),
                preferred_addr.get_ipv6_address(),
                preferred_addr.get_ipv6_port(),
                preferred_addr.get_connection_id()
            );

            // Check if migration is disabled
            if self.is_peer_migration_disabled() {
                warn!("Preferred address provided but peer has disabled active migration");
                return Ok(());
            }

            // Validate that the preferred address has a valid connection ID
            if preferred_addr.get_connection_id().is_empty() {
                warn!("Preferred address has empty connection ID, cannot migrate");
                return Ok(());
            }

            // Determine which preferred address to use (prioritize IPv4 for now)
            let preferred_socket_addr =
                if preferred_addr.get_ipv4_address() != std::net::Ipv4Addr::new(0, 0, 0, 0) {
                    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        preferred_addr.get_ipv4_address(),
                        preferred_addr.get_ipv4_port(),
                    ))
                } else if preferred_addr.get_ipv6_address()
                    != std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
                {
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        preferred_addr.get_ipv6_address(),
                        preferred_addr.get_ipv6_port(),
                        0,
                        0,
                    ))
                } else {
                    warn!("Preferred address has no valid IPv4 or IPv6 address");
                    return Ok(());
                };

            // Add the preferred address as a new path using the migration system
            // The preferred address connection ID should have sequence number 1
            // (sequence 0 is the initial connection ID from handshake)
            match self.migration.add_path_with_connection_id(
                preferred_addr.get_connection_id().clone(),
                preferred_socket_addr,
                self.migration.get_active_connection_id_sequence() + 1, // Must be one
                self.current_ts,
            ) {
                Ok(path_id) => {
                    info!(
                        "Added preferred address path: path_id={}, address={:?}, sequence=1",
                        path_id, preferred_socket_addr
                    );

                    self.create_and_send_path_challenge_for_path(path_id)?;
                }
                Err(e) => {
                    error!("Failed to add preferred address path: {}", e);
                }
            }
        } else {
            trace!("No preferred address provided by peer");
        }

        Ok(())
    }

    /// Validate client-specific transport parameters according to RFC 9000 Section 7.3
    ///
    /// This function validates transport parameters that are required for QUIC clients
    /// to verify when receiving them from the server during the handshake.
    fn validate_client_transport_parameters(&self) -> Result<()> {
        // RFC 9000 Section 7.3: Transport parameters are authenticated by including them in the
        // transport layer security (TLS) handshake. A client MUST validate that certain parameters
        // match values that were included in the connection attempt.

        // 1. Validate original_destination_connection_id (REQUIRED for clients)
        // RFC 9000 Section 18.2: A client MUST treat the absence of the
        // original_destination_connection_id transport parameter from the server
        // as a connection error of type TRANSPORT_PARAMETER_ERROR.
        match self
            .peer_transport_params
            .get_original_destination_connection_id()
        {
            Some(peer_original_dcid) => {
                if peer_original_dcid != &self.org_dcid {
                    error!(
                        "Transport parameter validation failed: original_destination_connection_id mismatch. \
                        Server sent {:x?}, expected {:x?}",
                        peer_original_dcid, self.org_dcid
                    );
                    return Err(anyhow!("original_destination_connection_id does not match"));
                }
                info!(
                    "Transport parameter validation passed: original_destination_connection_id={:x?}",
                    peer_original_dcid
                );
            }
            None => {
                error!("Transport parameter validation failed: server did not send original_destination_connection_id");
                return Err(anyhow!(
                    "Missing original_destination_connection_id transport parameter"
                ));
            }
        }

        // 2. Validate retry_source_connection_id (if a retry packet was received)
        // RFC 9000 Section 7.3: If a client receives a Retry packet, the transport parameters
        // sent by the server MUST include a retry_source_connection_id transport parameter.
        if self.retry_source_connection_id.is_some() {
            // We received a retry packet, so retry_source_connection_id MUST be present
            match self.peer_transport_params.get_retry_source_connection_id() {
                Some(retry_scid) => {
                    // The retry_source_connection_id should match the source connection ID
                    // from the Retry packet we received
                    info!(
                        "Transport parameter validation passed: retry_source_connection_id={:x?} \
                        (retry token present)",
                        retry_scid
                    );
                    // We already checked that self.retry_source_connection_id.is_some() above,
                    // so it's safe to unwrap here
                    if let Some(ref expected_retry_scid) = self.retry_source_connection_id {
                        if retry_scid != expected_retry_scid {
                            error!(
                                "Transport parameter validation failed: retry_source_connection_id mismatch. \
                                Server sent {:x?}, expected {:x?}",
                                retry_scid, expected_retry_scid
                            );
                            return Err(anyhow!("retry_source_connection_id does not match"));
                        }
                    }
                }
                None => {
                    error!(
                        "Transport parameter validation failed: retry_source_connection_id missing \
                        but retry token was received"
                    );
                    return Err(anyhow!(
                        "Missing retry_source_connection_id after receiving retry packet"
                    ));
                }
            }
        } else {
            // We did not receive a retry packet, so retry_source_connection_id MUST NOT be present
            if let Some(retry_scid) = self.peer_transport_params.get_retry_source_connection_id() {
                error!(
                    "Transport parameter validation failed: retry_source_connection_id={:x?} \
                    present but no retry packet was received",
                    retry_scid
                );
                return Err(anyhow!(
                    "Unexpected retry_source_connection_id without retry packet"
                ));
            }
        }

        info!("All client transport parameter validations passed successfully");
        Ok(())
    }

    /// Calculate a suggested retire_prior_to value based on our local connection IDs
    ///
    /// This function finds the minimum sequence number in our available_local_connection_ids
    /// to suggest as retire_prior_to when sending NEW_CONNECTION_ID frames. This tells the peer
    /// to retire all our connection IDs with sequence numbers less than this value.
    fn calculate_suggested_peer_retire_prior_to(&self) -> u64 {
        if self.available_local_connection_ids.is_empty() {
            return 0;
        }

        // Find the minimum sequence number in our available local connection IDs
        // This is the earliest connection ID we still have available
        let min_sequence = self
            .available_local_connection_ids
            .keys()
            .min()
            .copied()
            .unwrap_or(0);

        min_sequence
    }

    /// Generate a new local connection ID if we haven't reached the limit
    fn maybe_generate_new_local_connection_id(&mut self) -> Result<()> {
        if self.can_generate_local_connection_id() {
            self.generate_new_local_connection_id()?;
        }

        Ok(())
    }

    /// Generate and send a new local connection ID to the peer
    fn generate_new_local_connection_id(&mut self) -> Result<()> {
        self.generate_new_local_connection_id_with_retire_prior_to(None)
    }

    /// Generate and send a new local connection ID to the peer with optional retire_prior_to
    fn generate_new_local_connection_id_with_retire_prior_to(
        &mut self,
        retire_prior_to: Option<u64>,
    ) -> Result<()> {
        use crate::frame::QuicFrame;
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let sequence_number = self.next_local_connection_id_sequence;
        self.next_local_connection_id_sequence += 1;

        // Generate a new connection ID with the same length as our initial scid
        let cid_length = self.scid.len();
        let mut new_cid = vec![0u8; cid_length];
        rng.fill(&mut new_cid[..]);

        // Generate stateless reset token using cryptographic derivation
        let reset_token = QuicCrypto::generate_stateless_reset_token_with_key(
            &new_cid,
            self.quic_config.get_stateless_reset_key(),
        );

        // Store the new connection ID
        self.available_local_connection_ids
            .insert(sequence_number, (new_cid.clone(), reset_token));

        // Also add to lookup set for fast checking
        self.local_connection_ids_lookup.insert(new_cid.clone());

        // Determine retire_prior_to value
        let retire_prior_to_value = retire_prior_to.unwrap_or(self.suggested_peer_retire_prior_to);

        // Send NEW_CONNECTION_ID frame to peer
        let new_conn_id_frame = QuicFrame::create_new_connection_id_frame(
            sequence_number,
            retire_prior_to_value,
            &new_cid,
            &reset_token,
        );

        self.app_send.insert_send_queue_back(new_conn_id_frame);
        self.set_next_send_event_time(0);

        info!(
            "Generated new local connection ID: sequence={}, cid={:x?}, token={:x?}, retire_prior_to={}",
            sequence_number, new_cid, reset_token, retire_prior_to_value
        );

        Ok(())
    }

    fn get_local_connection_id_count(&self) -> usize {
        self.available_local_connection_ids.len()
    }

    /// Check if we can generate more local connection IDs
    fn can_generate_local_connection_id(&self) -> bool {
        let local_limit = self.get_peer_active_connection_id_limit();
        self.get_local_connection_id_count() < local_limit as usize
    }

    /// Generate and send initial local connection IDs to reach the configured limit
    fn generate_and_send_initial_local_connection_ids(&mut self) -> Result<()> {
        while self.can_generate_local_connection_id() {
            self.generate_new_local_connection_id()?;
        }

        Ok(())
    }
    fn send_retire_connection_id_frame(&mut self, sequence_number: u64) -> Result<()> {
        // Note: The actual removal is handled by the migration system
        let retire_frame = QuicFrame::create_retire_connection_id_frame(sequence_number);
        self.app_send.insert_send_queue_back(retire_frame);
        self.set_next_send_event_time(0);

        info!(
            "Sent RETIRE_CONNECTION_ID frame: sequence_number={}",
            sequence_number
        );

        Ok(())
    }

    pub(crate) fn handle_reset_stream_frame(
        &mut self,
        stream_id: u64,
        application_error_code: u64,
        final_size: u64,
    ) -> Result<()> {
        let handle = QuicStreamHandle::new(stream_id);
        let stream = self.streams.get_mut(&handle);

        match stream {
            Some(stream) => {
                info!(
                    "Handling RESET_STREAM frame for stream {} with error code {} and final size {}",
                    handle, application_error_code, final_size
                );
                stream
                    .handle_reset_stream_frame(application_error_code, final_size)
                    .with_context(|| {
                        format!("Failed to handle RESET_STREAM frame for stream {handle}")
                    })
            }
            None => {
                warn!(
                    "Received RESET_STREAM frame for non-existent stream {} with error code {}",
                    handle, application_error_code
                );
                Ok(())
            }
        }
    }

    pub(crate) fn handle_stop_sending_frame(
        &mut self,
        stream_id: u64,
        application_error_code: u64,
    ) -> Result<()> {
        let handle = QuicStreamHandle::new(stream_id);
        let stream = self.streams.get_mut(&handle);

        match stream {
            Some(stream) => {
                info!(
                    "Handling STOP_SENDING frame for stream {} with error code {}",
                    handle, application_error_code
                );
                if let Some(frame) = stream
                    .handle_stop_sending_frame(application_error_code)
                    .with_context(|| {
                        format!("Failed to handle STOP_SENDING frame for stream {handle}")
                    })?
                {
                    self.app_send.insert_send_queue_back(frame);
                    self.set_next_send_event_time(0);
                }
                Ok(())
            }
            None => {
                warn!(
                    "Received STOP_SENDING frame for non-existent stream {} with error code {}",
                    handle, application_error_code
                );
                Ok(())
            }
        }
    }

    pub(crate) fn handle_max_streams_frame(
        &mut self,
        is_bidirectional: bool,
        max_streams: u64,
    ) -> Result<()> {
        info!(
            "Handling MAX_STREAMS frame: is_bidirectional={}, max_streams={}",
            is_bidirectional, max_streams
        );
        self.flow_control
            .handle_max_streams_frame(is_bidirectional, max_streams)
    }

    pub(crate) fn handle_max_stream_data_frame(
        &mut self,
        stream_id: u64,
        max_stream_data: u64,
    ) -> Result<()> {
        let handle = QuicStreamHandle::new(stream_id);

        info!(
            "Handling MAX_STREAM_DATA frame: stream_id={}, max_stream_data={}",
            handle, max_stream_data
        );

        match self.streams.get_mut(&handle) {
            Some(stream) => stream
                .update_max_stream_data(max_stream_data)
                .with_context(|| format!("Failed to update max stream data for stream {handle}")),
            None => {
                warn!(
                    "Received MAX_STREAM_DATA frame for non-existent stream {} with max_stream_data={}",
                    handle, max_stream_data
                );
                Ok(())
            }
        }
    }

    pub(crate) fn handle_max_data_frame(&mut self, max_data: u64) -> Result<()> {
        trace!("Handling MAX_DATA frame: max_data={}", max_data);
        self.flow_control.handle_max_data_frame(max_data)
    }

    pub(crate) fn handle_connection_close_frame(
        &mut self,
        error_code: QuicConnectionErrorCode,
        reason: String,
        level: QuicLevel,
    ) -> Result<()> {
        if self.is_draining() {
            info!(
                "Got another error code {:?} from connection close frame, reason {}",
                error_code, reason
            );
            return Ok(());
        }

        if self.is_closing() {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2-3
            trace!(
                "As we are closing QUIC connection, peer side did the same, error_code {:?} \
                reason {}",
                error_code,
                reason
            );
            self.draining(level, false);
            return Ok(());
        }

        if self.is_closed() {
            error!(
                "As we closed QUIC connection, should not handle QUIC packet, error_code {:?} \
                reason {}",
                error_code, reason
            );
            return Ok(());
        }

        info!(
            "Received the Connection close frame, starting to enter Draining state, \
            error_code {:?}, reason {}",
            error_code, reason
        );

        self.peer_error_code = Some(error_code);
        self.peer_reason_phrase = Some(reason);

        self.draining(level, true);

        Ok(())
    }

    pub(crate) fn handle_streams_blocked_frame(
        &mut self,
        max_streams: u64,
        is_bidirectional: bool,
    ) -> Result<()> {
        info!(
            "Handling STREAMS_BLOCKED frame: max_streams={}, is_bidirectional {}",
            max_streams, is_bidirectional,
        );

        // TODO: Shall we send max streams frame?
        // update the local stream limitations?

        Ok(())
    }

    pub(crate) fn handle_data_blocked_frame(&mut self, max_data: u64) -> Result<()> {
        info!("Handling DATA_BLOCKED frame: max_data={}", max_data);
        if self.flow_control.check_if_update_max_recv_data(true) {
            self.create_and_insert_max_data_stream(None, self.flow_control.get_new_max_recv_size())
                .map_err(|e| QuicConnectionError::InternalError(format!("Due to {e}")))?;
        }
        Ok(())
    }

    pub(crate) fn handle_stream_data_blocked_frame(
        &mut self,
        stream_id: u64,
        max_stream_data: u64,
    ) -> Result<()> {
        let handle = QuicStreamHandle::new(stream_id);

        info!(
            "Handling STREAM_DATA_BLOCKED frame: stream_id={}, max_stream_data={}",
            handle, max_stream_data
        );

        match self.streams.get_mut(&handle) {
            Some(stream) => {
                let res = stream.check_if_update_max_recv_data(true);
                let stream_max_size = stream.get_new_max_recv_size();
                if res {
                    self.create_and_insert_max_data_stream(Some(handle), stream_max_size)
                        .with_context(|| {
                            format!("Failed to create MAX_STREAM_DATA frame for stream {handle}")
                        })?;
                }
                Ok(())
            }
            None => {
                warn!(
                    "Received STREAM_DATA_BLOCKED frame for non-existent stream {} with max_stream_data={}",
                    handle, max_stream_data
                );
                Ok(())
            }
        }
    }

    pub(crate) fn handle_stream_frame(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        type_bits: u64,
    ) -> Result<()> {
        // STREAM Frame {
        //   Type (i) = 0x08..0x0f,
        //   Stream ID (i),
        //   [Offset (i)],
        //   [Length (i)],
        //   Stream Data (..),
        // }

        let off_bit = type_bits & 0x04 > 0;
        let len_bit = type_bits & 0x02 > 0;
        let fin_bit = type_bits & 0x01 > 0;

        let stream_id = decode_variable_length(cursor)?;
        let handle = QuicStreamHandle::new(stream_id);

        let offset = if off_bit {
            decode_variable_length(cursor)?
        } else {
            0
        };

        let length = if len_bit {
            decode_variable_length(cursor)?
        } else {
            // When the LEN bit is set to 0, the Stream Data field consumes all the remaining bytes in the packet.
            remaining_bytes(cursor)?
        };

        match self.streams.entry(handle) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut()
                    .handle_stream_frame(offset, length, fin_bit, cursor)?;
                let should_clean = e.get().should_clean_stream();
                if should_clean {
                    self.clean_stream(handle);
                }
            }
            std::collections::hash_map::Entry::Vacant(_) => {
                self.recv_new_stream(handle, offset, length, fin_bit, cursor)?;
            }
        };

        // Check connection level flow control
        if self.flow_control.get_recv_available_bytes()? <= length {
            // Create flow control error and throw it
            let connection_error =
                crate::error_code::QuicConnectionErrorCode::create_transport_error_code(
                    u64::from(crate::error_code::TransportErrorCode::FlowControlError),
                    Some(crate::frame::QuicFrameType::Stream as u64), // STREAM frame type that triggered the flow control error
                );
            return Err(anyhow::Error::from(connection_error));
        }

        Ok(())
    }

    fn recv_new_stream(
        &mut self,
        stream_id: QuicStreamHandle,
        offset: u64,
        length: u64,
        fin_bit: bool,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<()> {
        if stream_id.is_client_initiated()
            && (stream_id.as_u64() < self.next_uni_local_stream_id
                || stream_id.as_u64() < self.next_bidi_local_stream_id)
        {
            info!(
                "Drop the stream frame, since stream {} could be closed",
                stream_id
            );
            return Ok(());
        } else if let Some(mrs) = self.max_remote_stream_id {
            if stream_id.as_u64() < mrs {
                info!(
                    "Drop the stream frame, since stream {} could be closed",
                    stream_id
                );
                return Ok(());
            }
        }

        QuicStream::check_new_stream_id(stream_id)?;

        if stream_id.is_bidirectional()
            && self
                .flow_control
                .get_max_streams_bidi_local()
                .map(|max| self.flow_control.get_bi_stream_remote_cnt() >= max)
                .unwrap_or(true)
        {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-3
            // Create stream limit error and throw it
            let connection_error =
                crate::error_code::QuicConnectionErrorCode::create_transport_error_code(
                    u64::from(crate::error_code::TransportErrorCode::StreamLimitError),
                    Some(crate::frame::QuicFrameType::Stream as u64), // STREAM frame type that triggered the flow control error
                );
            return Err(anyhow::Error::from(connection_error));
        }

        if !stream_id.is_bidirectional()
            && self
                .flow_control
                .get_max_streams_uni_local()
                .map(|max| self.flow_control.get_uni_stream_remote_cnt() >= max)
                .unwrap_or(true)
        {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-3
            // Create stream limit error and throw it
            let connection_error =
                crate::error_code::QuicConnectionErrorCode::create_transport_error_code(
                    u64::from(crate::error_code::TransportErrorCode::StreamLimitError),
                    Some(crate::frame::QuicFrameType::Stream as u64), // STREAM frame type that triggered the flow control error
                );
            return Err(anyhow::Error::from(connection_error));
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1-7
        // A stream ID that is used out of order results in all streams of that type
        // with lower-numbered stream IDs also being opened.

        let max_send_size = if stream_id.is_bidirectional() {
            self.get_peer_initial_max_stream_data_bidi_local()
                .unwrap_or(0)
        } else {
            0
        };

        let max_recv_size = if stream_id.is_bidirectional() {
            self.quic_config.get_initial_max_stream_data_bidi_remote()
        } else {
            self.get_peer_initial_max_stream_data_uni().unwrap_or(0)
        };

        info!(
            "Opening new stream from server side {} (max_send_size: {} \
            max_recv_size: {})",
            stream_id, max_send_size, max_recv_size
        );

        // Only supports QUIC client role
        let mut new_stream = QuicStream::new(stream_id, max_send_size, max_recv_size);
        new_stream.handle_stream_frame(offset, length, fin_bit, cursor)?;
        if stream_id.is_bidirectional() {
            self.flow_control.increment_bi_stream_remote();
        } else {
            self.flow_control.increment_uni_stream_remote();
        }
        self.max_remote_stream_id =
            Some(self.max_remote_stream_id.map_or(stream_id.as_u64(), |mrs| {
                if mrs < stream_id.as_u64() {
                    stream_id.as_u64()
                } else {
                    mrs
                }
            }));
        self.streams.insert(stream_id, new_stream);

        Ok(())
    }

    pub(crate) fn handle_acked_stream_frame(&mut self, frames: Vec<QuicFrame>) -> Result<()> {
        frames.iter().try_for_each(|frame| -> Result<()> {
            match frame {
                QuicFrame::Stream(f) => {
                    let handle = QuicStreamHandle::new(f.stream_id);
                    if let Some(stream) = self.streams.get_mut(&handle) {
                        stream.ack_stream(f)?;
                        self.flow_control.increment_sent_acked(f.length);
                        let should_clean = stream.should_clean_stream();
                        if should_clean {
                            self.clean_stream(handle);
                        }
                    } else {
                        info!(
                            "Acked stream frame {:?} belongs to unexisted stream",
                            f.stream_id
                        );
                    }
                }
                QuicFrame::ResetStream(f) => {
                    let handle = QuicStreamHandle::new(f.stream_id);
                    if let Some(stream) = self.streams.get_mut(&handle) {
                        stream.ack_reset_stream(f)?;
                        let should_clean = stream.should_clean_stream();
                        if should_clean {
                            self.clean_stream(handle);
                        }
                    } else {
                        info!(
                            "Acked reset stream frame {:?} belongs to unexisted stream",
                            f.stream_id
                        );
                    }
                }
                _ => panic!("Can not handle the unexpected frame {frame:?}"),
            }

            Ok(())
        })?;

        Ok(())
    }

    pub(crate) fn run_events<T>(&mut self, uctx: &mut QuicUserContext<T>) -> Result<()>
    where
        T: QuicCallbacks,
    {
        let span = span!(
            Level::TRACE,
            "quic_streams",
            scid = ?self.scid.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(""),
            dcid = ?self.format_span_dcid()
        );
        let _enter = span.enter();

        trace!("Processing events at {:?}", self.current_ts);
        if !self.connect_done_called {
            if self.is_established() {
                trace!("Connection established, calling connect done event");
                self.connect_done_called = true;
                uctx.run_connect_done_event(self, QuicConnectResult::Success)?;
            } else if self.is_closed() || self.is_draining() {
                self.connect_done_called = true;
                if self.idle_close_trigger {
                    uctx.run_connect_done_event(
                        self,
                        QuicConnectResult::Timeout(self.get_idle_timeout()),
                    )?;
                } else {
                    uctx.run_connect_done_event(
                        self,
                        QuicConnectResult::Failed(format!(
                            "{:?}, {:?}",
                            self.peer_error_code, self.peer_reason_phrase
                        )),
                    )?;
                }
            }
        }

        if let Some((old_path_id, new_path_id, result)) =
            self.migration.migration_result_pending.take()
        {
            uctx.run_migration_switch_result_event(self, old_path_id, new_path_id, result)?;
        }

        if !self.is_closed() && !self.is_closing() && !self.is_draining() {
            let mut read_ready_streams = vec![];
            let mut write_ready_streams = vec![];

            self.streams
                .iter_mut()
                .try_for_each(|(stream_id, stream)| -> Result<()> {
                    if stream.is_readable() {
                        trace!("Stream {} is readable", stream_id);
                        read_ready_streams.push(*stream_id);
                    }
                    if stream.is_writable() {
                        trace!("Stream {} is writable", stream_id);
                        write_ready_streams.push(*stream_id);
                    }
                    Ok(())
                })?;

            trace!(
                "Processing {} readable streams and {} writable streams",
                read_ready_streams.len(),
                write_ready_streams.len()
            );

            read_ready_streams
                .iter()
                .try_for_each(|stream_id| -> Result<()> {
                    trace!("Running read event for stream {}", stream_id);
                    uctx.run_read_event(self, *stream_id)
                })?;

            write_ready_streams
                .iter()
                .try_for_each(|stream_id| -> Result<()> {
                    trace!("Running write event for stream {}", stream_id);
                    uctx.run_write_event(self, *stream_id)
                })?;
        }

        if !self.is_draining() {
            self.consume_stream_send_queue()?;
        }

        if (self.is_draining()
            || self.is_closed()) // Could be idle timeout
            && !self.close_called
        {
            trace!("Connection closed, calling close event");
            self.close_called = true;
            uctx.run_close_event(
                self,
                self.peer_error_code.map(|e| e.get_error_code()),
                self.peer_reason_phrase.clone(),
            )?;
        }

        Ok(())
    }

    pub(crate) fn get_idle_timeout(&self) -> u64 {
        if let Some(idle_timeout) = self.idle_timeout {
            idle_timeout
        } else {
            self.quic_config.get_idle_timeout()
        }
    }

    fn consume_stream_send_queue(&mut self) -> Result<()> {
        // Consumes data from stream send queues and prepares it for transmission
        //
        // # Implementation Notes
        // - Currently implements round-robin scheduling for streams
        //
        // # TODO
        // - Optimize packetization to minimize stream multiplexing within a single datagram
        // - Implement congestion control window
        // - Add stream priority support
        let max_buf_size = self.get_mtu() as u64;
        loop {
            let mut has_data = false;

            self.streams.iter_mut().for_each(|(_, stream)| {
                if let Some((data, offset, stream_id, is_fin)) =
                    stream.consume_send_queue(max_buf_size)
                {
                    let send_ctx = &mut self.app_send;
                    send_ctx.insert_send_queue_with_stream_data(data, offset, stream_id, is_fin);
                    self.should_send_asap = true;
                }

                if !stream.send_queue_is_empty() {
                    has_data = true;
                }
            });
            if !has_data {
                break;
            }
        }

        Ok(())
    }

    pub(crate) fn consume_tls_send_queue(&mut self) -> Result<()> {
        while let Some((buf, level)) = self.tls.send() {
            let send_ctx = match level {
                QuicLevel::Initial => &mut self.init_send,
                QuicLevel::Handshake => &mut self.hs_send,
                QuicLevel::Application => &mut self.app_send,
            };
            trace!("Insert crypto frame into {:?} send queue", level);
            send_ctx.insert_send_queue_with_crypto_data(buf)?;
        }
        Ok(())
    }

    pub(crate) fn is_all_send_queue_empty(&self) -> bool {
        self.init_send.is_send_queue_empty()
            && self.hs_send.is_send_queue_empty()
            && self.app_send.is_send_queue_empty()
    }

    pub(crate) fn update_packet_send_queue(&mut self, new_pkt: Vec<Vec<u8>>) {
        // Get the target address from the current active path when inserting into queue
        let target_address = self.migration.get_current_target_address().unwrap();

        self.send_queue.push_back((new_pkt, target_address));
    }

    pub(crate) fn detect_lost(&mut self) -> Result<()> {
        for send_ctx in [&mut self.init_send, &mut self.hs_send, &mut self.app_send] {
            if send_ctx.detect_lost(&self.rtt, self.current_ts)? {
                self.should_send_asap = true;
                info!("Detect the packet loss, should retransmit packets immediately");
            }
        }

        Ok(())
    }

    pub(crate) fn should_update_key(&mut self) -> bool {
        // Ensure the first key has been used before allowing an key update
        if self.app_send.largest_acked.is_none() {
            return false;
        }

        let trigger_times = match self.quic_config.get_trigger_key_update() {
            Some(times) => times,
            None => return false,
        };

        // Check if the current packet number exceeds the trigger threshold
        let next_pn = self.app_send.get_next_packet_number();
        if trigger_times >= next_pn {
            return false;
        }

        // Reset the trigger to ensure one-time activation
        self.quic_config.clear_trigger_key_update();

        true
    }

    pub(crate) fn reset_pto_backoff_factor(&mut self) {
        self.pto_backoff = 0;
    }

    fn create_and_insert_streams_blocked_stream(
        &mut self,
        is_bidirectional: bool,
        max_streams: u64,
    ) -> Result<()> {
        let frame = QuicFrame::create_streams_blocked_frame(max_streams, is_bidirectional);

        self.app_send.insert_send_queue_front(frame);

        let datagram_buf = QuicPacket::create_quic_packet(self, QuicLevel::Application, 1)?
            .ok_or_else(|| anyhow!("Must create the QUIC packet successfully here"))?;
        self.update_packet_send_queue(vec![datagram_buf]);

        Ok(())
    }

    fn create_and_insert_data_blocked_stream(
        &mut self,
        stream_id: Option<QuicStreamHandle>,
        max_data: u64,
    ) -> Result<()> {
        let frame = if let Some(stream_id) = stream_id {
            QuicFrame::create_stream_data_blocked_frame(stream_id.as_u64(), max_data)
        } else {
            QuicFrame::create_data_blocked_frame(max_data)
        };

        self.app_send.insert_send_queue_front(frame);

        let datagram_buf = QuicPacket::create_quic_packet(self, QuicLevel::Application, 1)?
            .ok_or_else(|| anyhow!("Must create the QUIC packet successfully here"))?;
        self.update_packet_send_queue(vec![datagram_buf]);

        Ok(())
    }

    fn create_and_insert_max_data_stream(
        &mut self,
        stream_id: Option<QuicStreamHandle>,
        max_data: u64,
    ) -> Result<()> {
        let frame = if let Some(stream_id) = stream_id {
            QuicFrame::create_max_stream_data_frame(stream_id.as_u64(), max_data)
        } else {
            QuicFrame::create_max_data_frame(max_data)
        };

        self.app_send.insert_send_queue_front(frame);

        let datagram_buf = QuicPacket::create_quic_packet(self, QuicLevel::Application, 1)?
            .ok_or_else(|| anyhow!("Must create the QUIC packet successfully here"))?;
        self.update_packet_send_queue(vec![datagram_buf]);

        Ok(())
    }

    fn recreate_quic_packet_for_pto(&mut self, level: QuicLevel) -> Result<()> {
        // An endpoint SHOULD include new data in packets that are sent on PTO expiration.
        // Previously sent data MAY be sent if no new data can be sent. Implementations
        // MAY use alternative strategies for determining the content of probe packets,
        // including sending new or retransmitted data based on the application's priorities.
        let send_ctx = match level {
            QuicLevel::Initial => &mut self.init_send,
            QuicLevel::Handshake => &mut self.hs_send,
            QuicLevel::Application => &mut self.app_send,
        };

        if !send_ctx.resend_first_eliciting_frame() {
            let ping_frame = QuicFrame::Ping(QuicPing::default());
            send_ctx.insert_send_queue_front(ping_frame);
            trace!("Created {:?} ping frame", level);
        }

        let datagram_buf = QuicPacket::create_quic_packet(self, level, 1)?
            .ok_or_else(|| anyhow!("Must create the {:?} QUIC packet successfully here", level))?;
        self.update_packet_send_queue(vec![datagram_buf]);

        Ok(())
    }

    fn pto_handler(&mut self) -> Result<()> {
        let span = span!(Level::TRACE, "handling PTO");
        let _enter = span.enter();

        // https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4
        self.pto_threshold = None;
        let backoff_factor = 1 << self.pto_backoff;

        trace!("Current PTO backoff factor: {}", backoff_factor);

        // Helper closure to handle PTO for each level
        let mut handle_level_pto = |level: QuicLevel| -> Result<()> {
            if !self.crypto.is_key_available(level) {
                return Ok(());
            }

            let pto_timeout = self.rtt.get_pto(level) * backoff_factor;
            let send_ctx = match level {
                QuicLevel::Initial => &mut self.init_send,
                QuicLevel::Handshake => &mut self.hs_send,
                QuicLevel::Application => &mut self.app_send,
            };

            if let Some(pto_ts) = send_ctx.calculate_pto(pto_timeout, false)? {
                if pto_ts <= self.current_ts {
                    trace!(
                        "PTO triggered for {:?} level at {}",
                        level,
                        format_instant(pto_ts, self.current_ts)
                    );

                    // When a PTO timer expires, a sender MUST send at least one ack-eliciting packet
                    // in the packet number space as a probe. An endpoint MAY send up to two full-sized
                    // datagrams containing ack-eliciting packets to avoid an expensive consecutive PTO
                    // expiration due to a single lost datagram or to transmit data from multiple packet
                    // number spaces.
                    let tries = if self.pto_backoff >= 1 { 2 } else { 1 };
                    for _ in 0..tries {
                        self.recreate_quic_packet_for_pto(level)?;
                    }

                    // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1-3
                    // Also update the idle timer, when PTO timer fires
                    if self.pto_backoff == 0 {
                        self.update_idle_timeout_threshold();
                    }
                } else {
                    trace!(
                        "Skip this action {}",
                        format_instant(pto_ts, self.current_ts)
                    );
                }
            } else {
                trace!("No PTO timer here");
            }
            Ok(())
        };

        // Handle PTO for Initial level
        handle_level_pto(QuicLevel::Initial)?;

        // Handle PTO for Handshake level
        handle_level_pto(QuicLevel::Handshake)?;

        // Handle PTO for Application level (only after handshake is confirmed)
        handle_level_pto(QuicLevel::Application)?;

        if self.should_send_asap {
            info!("PTO triggered - packets will be sent immediately");
        } else {
            trace!("No PTO actions needed at this time");
        }

        Ok(())
    }

    pub(crate) fn set_loss_or_pto_timer(&mut self) -> Result<()> {
        if self.is_closed() || self.is_closing() || self.is_draining() {
            self.pto_threshold = None;
            self.detect_lost_threshold = None;
            return Ok(());
        }

        let span = span!(Level::TRACE, "setting Loss or PTO timer");
        let _enter = span.enter();

        self.pto_threshold = None;
        self.detect_lost_threshold = None;

        let backoff_factor = 1 << self.pto_backoff;
        let established = self.is_established();
        trace!("Current PTO backoff factor: {}", backoff_factor);

        // Helper closure to update PTO threshold
        let time_threshold = self.rtt.get_time_threhold();
        let mut update = |level: QuicLevel, send_ctx: &mut QuicSendContext| -> Result<()> {
            if let Some(detect_lost_ts) = send_ctx.calculate_loss(time_threshold)? {
                self.detect_lost_threshold = self
                    .detect_lost_threshold
                    .map_or(Some(detect_lost_ts), |org| Some(org.min(detect_lost_ts)));

                trace!(
                    "Update {:?} detect_lost_threshold to {}",
                    level,
                    format_instant(detect_lost_ts, self.current_ts)
                );
            }

            let pto_timeout = self.rtt.get_pto(level) * backoff_factor;
            if let Some(pto_ts) = send_ctx.calculate_pto(pto_timeout, true)? {
                self.pto_threshold = self
                    .pto_threshold
                    .map_or(Some(pto_ts), |org| Some(org.min(pto_ts)));
                trace!(
                    "Updated {:?} level PTO threshold to {}",
                    level,
                    format_instant(self.pto_threshold.unwrap(), self.current_ts)
                );
            }
            Ok(())
        };

        // Set PTO for Initial level
        if self.crypto.is_key_available(QuicLevel::Initial) {
            update(QuicLevel::Initial, &mut self.init_send)?;
        }

        // Set PTO for Handshake level
        if self.crypto.is_key_available(QuicLevel::Handshake) {
            update(QuicLevel::Handshake, &mut self.hs_send)?;
        }

        // Set PTO for Application level (only after handshake is confirmed)
        if established {
            update(QuicLevel::Application, &mut self.app_send)?;
        }

        if self.pto_threshold.is_some() {
            info!(
                "Now PTO threshold set to {} with backoff {}",
                format_instant(self.pto_threshold.unwrap(), self.current_ts),
                backoff_factor
            );
        } else {
            trace!("No PTO threshold was set");
        }

        if self.detect_lost_threshold.is_some() && self.pto_threshold.is_some() {
            info!(
                "Since we have detect_lost_threshold {} and pto_threshold {}, should disable PTO timer",
                format_instant(self.detect_lost_threshold.unwrap(), self.current_ts),
                format_instant(self.pto_threshold.unwrap(), self.current_ts)
            );
        }

        Ok(())
    }

    pub(crate) fn reset_ack_delay_threshold(&mut self) {
        self.ack_delay_threshold = None;
    }

    pub(crate) fn set_ack_delay_threshold(&mut self, timeout: u64) {
        self.ack_delay_threshold = self.current_ts.checked_add(Duration::from_millis(timeout));
        trace!(
            "Update ack delay threshold to {:?}, timeout {}",
            self.ack_delay_threshold,
            timeout
        );
    }

    pub(crate) fn set_oldkey_discard_time(&mut self, timeout: u64) {
        self.discard_oldkey_threshold = self.current_ts.checked_add(Duration::from_millis(timeout));
    }

    pub(crate) fn discard_keys(&mut self, level: QuicLevel) -> Result<()> {
        // https://www.rfc-editor.org/rfc/rfc9002.html#section-6.4
        self.crypto.discard_keys(level)?;

        let send_ctx = match level {
            QuicLevel::Initial => &mut self.init_send,
            QuicLevel::Handshake => &mut self.hs_send,
            QuicLevel::Application => &mut self.app_send,
        };
        send_ctx.clear();

        self.reset_pto_backoff_factor();
        self.set_loss_or_pto_timer()?;

        Ok(())
    }

    pub(crate) fn set_next_send_event_time(&mut self, ts: u64) {
        if ts == 0 {
            self.should_send_asap = true;
            return;
        }

        if self.send_event_threshold.is_none_or(|threshold| {
            self.current_ts
                .checked_add(Duration::from_millis(ts))
                .is_some_and(|new_ts| new_ts > threshold)
        }) {
            warn!(
                "Send event threshold was delayed, orginal send {:?}, ts {}",
                self.send_event_threshold, ts
            );
        }
        self.send_event_threshold = self.current_ts.checked_add(Duration::from_millis(ts));
    }

    fn expected_states(&self, s: Vec<QuicConnectionState>) -> Result<()> {
        if s.contains(&self.state) {
            Ok(())
        } else {
            Err(anyhow!(
                "Invalid QUIC connection state {:?}, expected {:?}",
                self.state,
                s
            ))
        }
    }

    fn expected_state(&self, s: QuicConnectionState) -> Result<()> {
        if s != self.state {
            return Err(anyhow!(
                "Invalid QUIC connection state {:?}, expected {:?}",
                self.state,
                s
            ));
        }

        Ok(())
    }

    pub(crate) fn handle_encrypted_extensions(&mut self) -> Result<()> {
        use crate::error_code::{QuicConnectionErrorCode, TransportErrorCode};
        use crate::frame::QuicFrameType;

        self.peer_transport_params.update_from_tls(&self.tls);

        // Validate client-specific transport parameters according to RFC 9000 Section 7.3
        if self.validate_client_transport_parameters().is_err() {
            let error_code = QuicConnectionErrorCode::create_transport_error_code(
                u64::from(TransportErrorCode::TransportParameterError),
                Some(QuicFrameType::Crypto as u64),
            );
            return Err(anyhow::Error::from(error_code));
        }

        // Update migration parameters from transport parameters
        self.peer_disable_active_migration = self
            .peer_transport_params
            .get_disable_active_migration()
            .unwrap_or(false);

        self.peer_active_connection_id_limit = self
            .peer_transport_params
            .get_active_connection_id_limit()
            .unwrap_or(MIN_ACTIVE_CONNECTION_ID_LIMIT);

        info!(
            "Updated migration parameters: disable_migration={}, connection_id_limit={}",
            self.peer_disable_active_migration, self.peer_active_connection_id_limit
        );

        // Handle stateless reset token from transport parameters
        // This typically corresponds to the initial connection ID (sequence 0)
        if let Some(rt) = self.peer_transport_params.get_stateless_reset_token() {
            if rt.len() as u16 == QUIC_STATELESS_RESET_TOKEN_SIZE {
                let mut reset_token_array = [0u8; QUIC_STATELESS_RESET_TOKEN_SIZE as usize];
                reset_token_array.copy_from_slice(&rt);

                // If we have a current connection ID from handshake, update/associate the reset token
                let current_dcid = self.migration.get_current_connection_id();
                let current_seq = self.migration.get_active_connection_id_sequence();
                if let Some(dcid) = current_dcid {
                    let dcid_vec = dcid.to_vec();
                    let dcid_debug = dcid.to_vec(); // For logging
                                                    // Update the existing entry or insert if it doesn't exist
                    self.migration.add_peer_connection_id(
                        current_seq, // Must be zero
                        dcid_vec,
                        reset_token_array,
                    )?;
                    info!(
                        "Updated handshake connection ID with transport parameter reset token: seq={}, cid={:x?}, token={:x?}",
                        current_seq, dcid_debug, reset_token_array
                    );
                }
            }
        }

        self.flow_control.set_initial_limits(
            self.quic_config.get_initial_max_data(),
            self.get_peer_initial_max_data().unwrap_or(0),
            self.quic_config.get_initial_max_streams_bidi(),
            self.quic_config.get_initial_max_streams_uni(),
            self.get_peer_initial_max_streams_bidi().unwrap_or(0),
            self.get_peer_initial_max_streams_uni().unwrap_or(0),
        );

        Ok(())
    }

    // Replace all the get_peer_* methods with direct access to peer_transport_params
    pub(crate) fn get_peer_max_udp_payload_size(&self) -> Option<u16> {
        self.peer_transport_params.get_max_udp_payload_size()
    }

    pub(crate) fn get_peer_max_idle_timeout(&self) -> Option<u64> {
        self.peer_transport_params.get_max_idle_timeout()
    }

    pub(crate) fn get_peer_max_ack_delay(&self) -> Option<u16> {
        self.peer_transport_params.get_max_ack_delay()
    }

    pub(crate) fn get_peer_ack_delay_exponent(&self) -> Option<u8> {
        self.peer_transport_params.get_ack_delay_exponent()
    }

    pub(crate) fn get_peer_initial_max_stream_data_bidi_local(&self) -> Option<u64> {
        self.peer_transport_params
            .get_initial_max_stream_data_bidi_local()
    }

    pub(crate) fn get_peer_initial_max_stream_data_bidi_remote(&self) -> Option<u64> {
        self.peer_transport_params
            .get_initial_max_stream_data_bidi_remote()
    }

    pub(crate) fn get_peer_initial_max_stream_data_uni(&self) -> Option<u64> {
        self.peer_transport_params.get_initial_max_stream_data_uni()
    }

    pub(crate) fn get_peer_initial_max_streams_bidi(&self) -> Option<u64> {
        self.peer_transport_params.get_initial_max_streams_bidi()
    }

    pub(crate) fn get_peer_initial_max_streams_uni(&self) -> Option<u64> {
        self.peer_transport_params.get_initial_max_streams_uni()
    }

    pub(crate) fn get_peer_initial_max_data(&self) -> Option<u64> {
        self.peer_transport_params.get_initial_max_data()
    }

    /// Check if peer has disabled active migration
    pub(crate) fn is_peer_migration_disabled(&self) -> bool {
        self.peer_disable_active_migration
    }

    /// Get peer's preferred address for connection migration
    pub(crate) fn get_peer_preferred_address(
        &self,
    ) -> Option<&crate::transport_parameters::PreferredAddress> {
        self.peer_transport_params.get_preferred_address()
    }

    /// Get peer's active connection ID limit
    pub(crate) fn get_peer_active_connection_id_limit(&self) -> u8 {
        self.peer_active_connection_id_limit
    }

    pub(crate) fn get_local_connection_id_limit(&self) -> u8 {
        self.quic_config.get_active_connection_id_limit()
    }

    fn discard_keys_safely(&mut self, level: QuicLevel) {
        if let Err(e) = self.discard_keys(level) {
            error!("Failed to discard {:?} keys: {}", level, e);
        }
    }

    pub(crate) fn get_mtu(&self) -> u16 {
        self.mtu.get_mtu()
    }

    fn start_mtu_discovery(&mut self) -> Result<()> {
        if let Some(target_mtu) = self.mtu.start_probe(&[self.app_send.next_pn]) {
            self.create_mtu_probe_packet(target_mtu)?;
            self.mtu_probe_timeout_threshold = self
                .current_ts
                .checked_add(Duration::from_millis(self.mtu.get_probe_timeout()));
            info!(
                "MTU probe timeout threshold: {:?}, next probe: {}",
                format_instant(self.mtu_probe_timeout_threshold.unwrap(), self.current_ts),
                target_mtu
            );
        }

        Ok(())
    }

    fn mtu_handler(&mut self) -> Result<()> {
        // Check if hit probe loss
        self.mtu_probe_timeout_threshold = None;
        info!("MTU handler called");

        if let Some(next_probe) = self.mtu.probe_failed() {
            // Send two probe packets to improve detection reliability
            self.create_mtu_probe_packet(next_probe)?;
            self.create_mtu_probe_packet(next_probe)?;
            self.mtu_probe_timeout_threshold = self
                .current_ts
                .checked_add(Duration::from_millis(self.mtu.get_probe_timeout()));
            info!(
                "MTU probe failed, threshold: {:?}, next probe: {}",
                format_instant(self.mtu_probe_timeout_threshold.unwrap(), self.current_ts),
                next_probe
            );
        } else {
            info!(
                "MTU discovery completed successfully, final MTU: {}",
                self.get_mtu()
            );
        }

        Ok(())
    }

    pub(crate) fn get_mtu_probe_pns(&self) -> Option<HashSet<u64>> {
        self.mtu.get_mtu_probe_pns()
    }

    pub(crate) fn handle_acked_mtu_probe(
        &mut self,
        acked_pns: Option<&HashSet<u64>>,
    ) -> Result<()> {
        if let Some(pns) = acked_pns {
            trace!("Handle mtu not acked probe pns {:?}", pns);

            if !pns.is_empty() {
                return Ok(());
            }

            if let Some(next_probe) = self.mtu.probe_success(self.app_send.next_pn) {
                info!(
                    "MTU success, threshold: {:?}, next probe: {}, pn {}",
                    format_instant(self.mtu_probe_timeout_threshold.unwrap(), self.current_ts),
                    next_probe,
                    self.app_send.next_pn
                );
                self.create_mtu_probe_packet(next_probe)?;
                self.mtu_probe_timeout_threshold = self
                    .current_ts
                    .checked_add(Duration::from_millis(self.mtu.get_probe_timeout()));
            } else {
                info!(
                    "MTU discovery completed successfully, final MTU: {}",
                    self.get_mtu()
                );
                self.mtu_probe_timeout_threshold = None;
            }
        }

        Ok(())
    }

    pub(crate) fn get_mtu_probe_size(&self) -> Option<u16> {
        self.mtu_probe_size
    }

    fn create_mtu_probe_packet(&mut self, mtu: u16) -> Result<()> {
        // TODO: Consider coalescing mtu probe with a Long Header QUIC packet
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-14.4.1
        let ping_frame = QuicFrame::Ping(QuicPing::default());
        self.app_send.insert_send_queue_front(ping_frame);
        self.mtu_probe_size = Some(mtu);
        let datagram_buf = QuicPacket::create_quic_packet(self, QuicLevel::Application, 1)?
            .ok_or_else(|| anyhow!("Must create the mtu probe QUIC packet successfully here"))?;
        self.mtu_probe_size = None;
        self.update_packet_send_queue(vec![datagram_buf]);
        self.set_next_send_event_time(0);

        Ok(())
    }

    pub(crate) fn format_span_dcid(&self) -> String {
        self.migration
            .get_current_dcid()
            .as_ref()
            .map(|d| {
                d.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<String>>()
                    .join("")
            })
            .or_else(|| {
                Some(
                    self.org_dcid
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<String>>()
                        .join(""),
                )
            })
            .unwrap_or_default()
    }

    pub(crate) fn reset_mtu(&mut self) {
        self.mtu.reset();
        self.mtu_probe_size = None;
        self.mtu_probe_timeout_threshold = None;
        info!("Reset MTU discovery");
    }
}
