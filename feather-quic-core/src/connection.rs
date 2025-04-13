use anyhow::{anyhow, Context, Result};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::io::Cursor;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{error, info, span, trace, warn, Level};

use crate::config::QuicConfig;
use crate::crypto::QuicCrypto;
use crate::flow_control::QuicConnectionFlowControl;
use crate::frame::{QuicFrame, QuicPing};
use crate::packet::QuicPacket;
use crate::rtt::QuicRttGenerator;
use crate::runtime::QuicUserContext;
use crate::send::QuicSendContext;
use crate::stream::{QuicStream, QuicStreamError, QuicStreamHandle};
use crate::tls::TlsContext;
use crate::transport_parameters::PeerTransportParameters;
use crate::utils::{decode_variable_length, format_instant, remaining_bytes};
use crate::QuicCallbacks;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum QuicLevel {
    Initial,
    Handshake,
    Application,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum QuicConnectionState {
    Init,
    Connecting,
    Established,
    _ConnectionClose,
}

#[derive(Error, Debug)]
pub enum QuicConnectionError {
    #[error("Stream {0} doesn't exist!")]
    StreamNotExist(QuicStreamHandle),

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-6
    #[error("Can not open {0} stream, current limitation is {1:?}!")]
    StreamLimitations(String, Option<u64>),

    #[error("Can not send any byte, current connection max data is {0}!")]
    StreamConnectionMaxDataLimitations(u64),

    #[error("Error from QUIC stream")]
    QuicStreamError(#[from] QuicStreamError),

    #[error("Interner implementation error {0}")]
    InternerError(String),
}

pub struct QuicConnection {
    pub(crate) quic_config: QuicConfig,
    state: QuicConnectionState,
    pub(crate) current_ts: Instant,
    pub(crate) idle_timeout: Option<u64>,
    idle_timeout_threshold: Option<Instant>,

    pub(crate) datagram_size: u16,
    pub(crate) scid: Vec<u8>,
    pub(crate) org_dcid: Vec<u8>,
    pub(crate) dcid: Option<Vec<u8>>,
    pub(crate) crypto: QuicCrypto,
    pub(crate) tls: TlsContext,
    pub(crate) retry_token: Option<Vec<u8>>,
    pub(crate) new_token: Option<Vec<u8>>,
    pub(crate) new_conn_ids: Vec<(Vec<u8>, Vec<u8>)>,

    pub(crate) key_phase: u8,
    discard_oldkey_threshold: Option<Instant>,
    detect_lost_threshold: Option<Instant>,
    pto_backoff: u16,
    pto_threshold: Option<Instant>,
    ack_delay_threshold: Option<Instant>,

    should_send_asap: bool,
    send_event_threshold: Option<Instant>,

    send_queue: VecDeque<Vec<Vec<u8>>>, // UDP datagram could carry multiple Long Header QUIC packet
    pub(crate) init_send: QuicSendContext,
    pub(crate) hs_send: QuicSendContext,
    pub(crate) app_send: QuicSendContext,

    pub(crate) rtt: QuicRttGenerator,

    connect_done: bool,
    peer_transport_params: PeerTransportParameters,

    // QUIC Streams
    streams: HashMap<QuicStreamHandle, QuicStream>,
    next_bidi_local_stream_id: u64,
    next_uni_local_stream_id: u64,
    max_remote_stream_id: Option<u64>,
    flow_control: QuicConnectionFlowControl,
}

#[allow(dead_code)]
impl QuicConnection {
    pub fn new(mut quic_config: QuicConfig) -> Self {
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

        let now = Instant::now();

        QuicConnection {
            state: QuicConnectionState::Init,
            crypto: QuicCrypto::default(),
            tls: TlsContext::new(&quic_config, &scid),
            current_ts: now,
            idle_timeout_threshold: None,
            scid,
            dcid: None,
            retry_token: None,
            new_token: None,
            idle_timeout: None,
            org_dcid,
            quic_config,
            new_conn_ids: vec![],

            datagram_size: 1200,
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
            connect_done: false,
            peer_transport_params: PeerTransportParameters::new(),
            flow_control: QuicConnectionFlowControl::new(),
        }
    }

    pub fn is_readable(&self) -> bool {
        false
    }

    pub fn is_writable(&self) -> bool {
        false
    }

    pub fn is_established(&self) -> bool {
        self.state == QuicConnectionState::Established
    }

    pub(crate) fn set_connected(&mut self) -> Result<()> {
        if self.state == QuicConnectionState::Established {
            return Ok(());
        }
        self.expected_state(QuicConnectionState::Connecting)?;
        self.state = QuicConnectionState::Established;
        Ok(())
    }

    // TODO: Support custom timestamp callback
    pub fn update_current_time(&mut self) {
        self.current_ts = Instant::now();
    }

    pub fn run_timer(&mut self) -> Result<()> {
        let span = span!(Level::TRACE, "processing timers");
        let _enter = span.enter();
        trace!("Enter processing timers, current_ts {:?}", self.current_ts);

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
                // TODO: Implement QUIC connection termination
                unimplemented!();
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

        trace!("Leave processing timers");

        Ok(())
    }

    pub fn next_time(&self) -> Option<u64> {
        let span = span!(Level::TRACE, "calculating next timer");
        let _enter = span.enter();

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
        let pto = time_until("PTO", self.pto_threshold);
        let ack_delay = time_until("ACK delay", self.ack_delay_threshold);

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
            .min(ack_delay);

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

    #[allow(unused_variables)]
    pub fn provide_data(&mut self, rcvbuf: &[u8], source_addr: SocketAddr) -> Result<()> {
        let span = span!(Level::TRACE, "providing data");
        let _enter = span.enter();

        QuicPacket::handle_quic_packet(rcvbuf, self, &source_addr).with_context(|| {
            format!(
                "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                self.scid, self.dcid, self.org_dcid
            )
        })?;

        // Update idle timeout threshold
        let idle_timeout = self.get_idle_timeout();
        self.idle_timeout_threshold = if idle_timeout != 0 {
            self.current_ts
                .checked_add(Duration::from_millis(idle_timeout))
        } else {
            None
        };

        Ok(())
    }

    pub fn consume_data(&mut self) -> Option<Vec<u8>> {
        let span = span!(Level::TRACE, "consuming data");
        let _enter = span.enter();
        if !self.send_queue.is_empty() {
            if let Err(e) = self.set_loss_or_pto_timer() {
                error!("Failed to set loss or pto timer during consuming send queue, due to {e}");
            }
        }

        self.send_queue
            .pop_front()
            .map(|v| v.into_iter().flat_map(|v| v.into_iter()).collect())
    }

    pub fn connect(&mut self) -> Result<()> {
        let span = span!(
            Level::TRACE,
            "connecting",
            scid = ?self.scid.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(""),
        );
        let _enter = span.enter();

        self.expected_state(QuicConnectionState::Init)
            .with_context(|| {
                format!(
                    "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                    self.scid, self.dcid, self.org_dcid
                )
            })?;
        self.state = QuicConnectionState::Connecting;
        self.update_current_time();
        QuicPacket::start_tls_handshake(self, false).with_context(|| {
            format!(
                "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                self.scid, self.dcid, self.org_dcid
            )
        })?;

        // Update idle timeout threshold
        let idle_timeout = self.get_idle_timeout();
        self.idle_timeout_threshold = if idle_timeout != 0 {
            self.current_ts
                .checked_add(Duration::from_millis(idle_timeout))
        } else {
            None
        };

        Ok(())
    }

    pub fn open_stream(
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
            .map_err(|e| QuicConnectionError::InternerError(format!("Due to {}", e)))?;
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
            .map_err(|e| QuicConnectionError::InternerError(format!("Due to {}", e)))?;

            return Err(QuicConnectionError::StreamLimitations(
                "Unidirectional".to_string(),
                self.flow_control.get_max_streams_uni_remote(),
            ));
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
                panic!("Stream {:?} already exists", e);
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
    pub fn stream_finish(
        &mut self,
        stream_handle: QuicStreamHandle,
    ) -> Result<(), QuicConnectionError> {
        let span = span!(Level::TRACE, "finishing stream", stream = ?stream_handle);
        let _enter = span.enter();

        let stream = self.streams.get_mut(&stream_handle).ok_or_else(|| {
            error!("Stream {:?} not found when trying to finish", stream_handle);
            QuicConnectionError::StreamNotExist(stream_handle)
        })?;

        info!("Finishing stream {:?}", stream_handle);
        Ok(stream.finish()?)
    }

    /// Reset the QUIC stream sending immediately
    pub fn stream_shutdown_write(
        &mut self,
        stream_handle: QuicStreamHandle,
        application_error_code: u64,
    ) -> Result<(), QuicConnectionError> {
        let span = span!(Level::TRACE, "shutting down stream write",
            stream = ?stream_handle,
            error_code = application_error_code
        );
        let _enter = span.enter();

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

        // Shall we discard the all related stream frames in the send queue?
        // Yes
        // A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for a stream
        // in the "Reset Sent" state or any terminal state
        // -- that is, after sending a RESET_STREAM frame.

        Ok(())
    }

    /// Reset the QUIC stream receiving immediately
    pub fn stream_shutdown_read(
        &mut self,
        stream_handle: QuicStreamHandle,
        application_error_code: u64,
    ) -> Result<()> {
        let span = span!(Level::TRACE, "shutting down stream read",
            stream = ?stream_handle,
            error_code = application_error_code
        );
        let _enter = span.enter();

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

        Ok(())
    }

    pub fn stream_recv(
        &mut self,
        stream_handle: QuicStreamHandle,
        recv_len: usize,
    ) -> Result<Vec<u8>, QuicConnectionError> {
        let span = span!(Level::TRACE, "receiving from stream",
            stream = ?stream_handle,
            length = recv_len
        );
        let _enter = span.enter();

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
                        QuicConnectionError::InternerError(format!(
                            "Stream {} failure, due to {}",
                            stream_handle, e
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
                .map_err(|e| QuicConnectionError::InternerError(format!("Due to {}", e)))?;
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

    pub fn stream_send(
        &mut self,
        stream_handle: QuicStreamHandle,
        snd_buf: &[u8],
    ) -> Result<usize, QuicConnectionError> {
        let span = span!(Level::TRACE, "sending to stream",
            stream = ?stream_handle,
            length = snd_buf.len()
        );
        let _enter = span.enter();

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
            .map_err(|e| QuicConnectionError::InternerError(format!("Due to {}", e)))?;

        if available_bytes == 0 {
            // Actually QUIC stream frame length can be zero, but we provide the `finish` api
            warn!("Connection flow control was triggered here");
            let max_send_size = self.flow_control.get_max_send_size();
            self.create_and_insert_data_blocked_stream(None, max_send_size)
                .map_err(|e| QuicConnectionError::InternerError(format!("Due to {}", e)))?;

            return Err(QuicConnectionError::StreamConnectionMaxDataLimitations(
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
                        .map_err(|e| QuicConnectionError::InternerError(format!("Due to {}", e)))?;
                }
                Err(QuicConnectionError::QuicStreamError(e))
            }
        }
    }

    pub fn set_stream_write_active(
        &mut self,
        stream_handle: QuicStreamHandle,
        flag: bool,
    ) -> Result<(), QuicConnectionError> {
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

    pub fn set_stream_read_active(
        &mut self,
        stream_handle: QuicStreamHandle,
        flag: bool,
    ) -> Result<(), QuicConnectionError> {
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

    pub(crate) fn handle_reset_stream_frame(
        &mut self,
        stream_id: u64,
        application_error_code: u64,
        final_size: u64,
    ) -> Result<()> {
        let handle = QuicStreamHandle::new(stream_id);
        let stream = self
            .streams
            .get_mut(&handle)
            .ok_or_else(|| anyhow!("The receiving stream doesn't exist {}", stream_id))?;

        stream.handle_reset_stream_frame(application_error_code, final_size)
    }

    pub(crate) fn handle_stop_sending_frame(
        &mut self,
        stream_id: u64,
        application_error_code: u64,
    ) -> Result<()> {
        let handle = QuicStreamHandle::new(stream_id);
        let stream = self
            .streams
            .get_mut(&handle)
            .ok_or_else(|| anyhow!("The sending stream doesn't exist {}", stream_id))?;

        if let Some(frame) = stream.handle_stop_sending_frame(application_error_code)? {
            self.app_send.insert_send_queue_back(frame);
        }

        Ok(())
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
        info!(
            "Handling MAX_STREAM_DATA frame: stream_id={}, max_stream_data={}",
            stream_id, max_stream_data
        );
        let stream = self
            .streams
            .get_mut(&QuicStreamHandle::new(stream_id))
            .ok_or_else(|| anyhow!("The stream doesn't exist {}", stream_id))?;

        // Update the stream's max data limit
        stream.update_max_stream_data(max_stream_data)?;

        Ok(())
    }

    pub(crate) fn handle_max_data_frame(&mut self, max_data: u64) -> Result<()> {
        trace!("Handling MAX_DATA frame: max_data={}", max_data);
        self.flow_control.handle_max_data_frame(max_data)
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
                .map_err(|e| QuicConnectionError::InternerError(format!("Due to {}", e)))?;
        }
        Ok(())
    }

    pub(crate) fn handle_stream_data_blocked_frame(
        &mut self,
        stream_id: u64,
        max_stream_data: u64,
    ) -> Result<()> {
        let stream_id = QuicStreamHandle::new(stream_id);
        info!(
            "Handling STREAM_DATA_BLOCKED frame: stream_id={}, max_stream_data={}",
            stream_id, max_stream_data
        );
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let res = stream.check_if_update_max_recv_data(true);
            let stream_max_size = stream.get_new_max_recv_size();
            if res {
                self.create_and_insert_max_data_stream(Some(stream_id), stream_max_size)
                    .map_err(|e| {
                        QuicConnectionError::InternerError(format!(
                            "Stream {} failure, due to {}",
                            stream_id, e
                        ))
                    })?;
            }
        }
        Ok(())
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
            return Err(anyhow!(
                "Receive connection flow control limit exceeded, \
                available_bytes {}, stream offset {}, stream length {}",
                self.flow_control.get_recv_available_bytes()?,
                offset,
                length
            ));
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
            // TODO: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-3
            // QUIC Termination
            return Err(anyhow!(
                "Can not open bidirectional stream, current limitation is {:?}!",
                self.flow_control.get_max_streams_bidi_remote()
            ));
        }

        if !stream_id.is_bidirectional()
            && self
                .flow_control
                .get_max_streams_uni_local()
                .map(|max| self.flow_control.get_uni_stream_remote_cnt() >= max)
                .unwrap_or(true)
        {
            // TODO: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-3
            // QUIC Termination
            return Err(anyhow!(
                "Can not open unidirectional stream, current limitation is {:?}!",
                self.flow_control.get_max_streams_uni_local()
            ));
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
                _ => panic!("Can not handle the unexpected frame {:?}", frame),
            }

            Ok(())
        })?;

        Ok(())
    }

    pub(crate) fn run_events<T>(&mut self, uctx: &mut QuicUserContext<T>) -> Result<()>
    where
        T: QuicCallbacks,
    {
        let span = span!(Level::TRACE, "handling Quic streams");
        let _enter = span.enter();

        // TODO: connect could fail
        if self.is_established() && !self.connect_done {
            self.connect_done = true;
            uctx.run_connect_done_event(self)?;
        }

        let mut read_ready_streams = vec![];
        let mut write_ready_streams = vec![];

        self.streams
            .iter_mut()
            .try_for_each(|(stream_id, stream)| -> Result<()> {
                if stream.is_readable() {
                    read_ready_streams.push(*stream_id);
                }
                if stream.is_writable() {
                    write_ready_streams.push(*stream_id);
                }
                Ok(())
            })?;

        read_ready_streams
            .iter()
            .try_for_each(|stream_id| -> Result<()> { uctx.run_read_event(self, *stream_id) })?;

        write_ready_streams
            .iter()
            .try_for_each(|stream_id| -> Result<()> { uctx.run_write_event(self, *stream_id) })?;

        self.consume_stream_send_queue()?;

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
        let max_buf_size = self.datagram_size as u64;
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
        self.send_queue.push_back(new_pkt);
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
                    let tries = if self.pto_backoff > 1 { 2 } else { 1 };
                    for _ in 0..tries {
                        self.recreate_quic_packet_for_pto(level)?;
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
        send_ctx.clear()?;

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

    pub(crate) fn handle_encrypted_extensions(&mut self) {
        self.peer_transport_params.update_from_tls(&self.tls);
        self.flow_control.set_initial_limits(
            self.quic_config.get_initial_max_data(),
            self.get_peer_initial_max_data().unwrap_or(0),
            self.quic_config.get_initial_max_streams_bidi(),
            self.quic_config.get_initial_max_streams_uni(),
            self.get_peer_initial_max_streams_bidi().unwrap_or(0),
            self.get_peer_initial_max_streams_uni().unwrap_or(0),
        );
    }

    // Replace all the get_peer_* methods with direct access to peer_transport_params
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
}
