use anyhow::{anyhow, Context, Result};
use rand::Rng;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{error, info, span, trace, warn, Level};

use crate::config::QuicConfig;
use crate::crypto::QuicCrypto;
use crate::frame::QuicFrame;
use crate::packet::QuicPacket;
use crate::rtt::QuicRttGenerator;
use crate::send::QuicSendContext;
use crate::tls::TlsContext;
use crate::utils::format_instant;

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
            init_send: QuicSendContext::default(),
            hs_send: QuicSendContext::default(),
            app_send: QuicSendContext::default(),

            rtt: QuicRttGenerator::default(),
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

    pub(crate) fn get_idle_timeout(&self) -> u64 {
        if let Some(idle_timeout) = self.idle_timeout {
            idle_timeout
        } else {
            self.quic_config.get_idle_timeout()
        }
    }

    pub(crate) fn consume_tls_send_queue(&mut self) -> Result<()> {
        if self.tls.should_send_tls() {
            while let Some((buf, level)) = self.tls.send() {
                let send_ctx = match level {
                    QuicLevel::Initial => &mut self.init_send,
                    QuicLevel::Handshake => &mut self.hs_send,
                    QuicLevel::Application => &mut self.app_send,
                };
                trace!("Insert crypto frame into {:?} send queue", level);
                send_ctx.insert_send_queue_with_crypto_data(buf)?;
            }
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
            send_ctx.create_and_insert_ping_frame()?;
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

            if let Some(pto_ts) = send_ctx.calculate_pto(pto_timeout, level, false)? {
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
                    if matches!(level, QuicLevel::Application) {
                        // TODO: send the unacked stream data
                        // Or send two PING frames over QUIC packets for probing
                        // https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4-3
                        for _ in 0..2 {
                            QuicFrame::create_and_insert_ping_frame(self, level)?;
                            let datagram_buf = QuicPacket::create_quic_packet(self, level, 1)?
                                .ok_or_else(|| {
                                    anyhow!("Must create the QUIC packet successfully here")
                                })?;
                            self.update_packet_send_queue(vec![datagram_buf]);
                        }
                    } else {
                        let tries = if self.pto_backoff > 1 { 2 } else { 1 };
                        for _ in 0..tries {
                            self.recreate_quic_packet_for_pto(level)?;
                        }
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
            if let Some(pto_ts) = send_ctx.calculate_pto(pto_timeout, level, true)? {
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
        send_ctx.clear(level)?;

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
}
