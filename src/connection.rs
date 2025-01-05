use anyhow::{anyhow, Context, Result};
use rand::Rng;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{info, span, trace, warn, Level};

use crate::config::QuicConfig;
use crate::crypto::QuicCrypto;
use crate::packet::QuicPacket;
use crate::send::QuicSendContext;
use crate::tls::TlsContext;

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
    current_ts: Instant,
    pub(crate) idle_timeout: Option<u64>,
    idle_timeout_threshold: Option<Instant>,

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

    send_queue: VecDeque<Vec<Vec<u8>>>, // UDP datagram could carry multiple Long Header QUIC packet
    pub(crate) init_send: QuicSendContext,
    pub(crate) hs_send: QuicSendContext,
    pub(crate) app_send: QuicSendContext,
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
        let threshold = if quic_config.get_idle_timeout() != 0 {
            now.checked_add(Duration::from_millis(quic_config.get_idle_timeout()))
        } else {
            None
        };

        QuicConnection {
            state: QuicConnectionState::Init,
            crypto: QuicCrypto::default(),
            tls: TlsContext::new(&quic_config, &scid),
            current_ts: now,
            idle_timeout_threshold: threshold,
            scid,
            dcid: None,
            retry_token: None,
            new_token: None,
            idle_timeout: None,
            org_dcid,
            quic_config,
            new_conn_ids: vec![],

            key_phase: 0,
            discard_oldkey_threshold: None,

            send_queue: VecDeque::new(),
            init_send: QuicSendContext::default(),
            hs_send: QuicSendContext::default(),
            app_send: QuicSendContext::default(),
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
        self.expected_state(QuicConnectionState::Connecting)?;
        self.state = QuicConnectionState::Established;
        Ok(())
    }

    pub fn update_current_time(&mut self) {
        self.current_ts = Instant::now();
    }

    pub fn run_timer(&mut self) -> Result<()> {
        let span = span!(Level::TRACE, "processing timers");
        let _enter = span.enter();
        self.update_current_time();

        if let Some(idle_timeout_threshold) = self.idle_timeout_threshold {
            if self.current_ts >= idle_timeout_threshold {
                warn!("Should shut down QUIC connection, due to idle timeout");
                // TODO: Implement QUIC connection termination
            }
        }

        if let Some(discard_oldkey_threshold) = self.discard_oldkey_threshold.as_ref() {
            if *discard_oldkey_threshold <= self.current_ts {
                info!(
                    "We need to discard last key here, {:?}",
                    discard_oldkey_threshold
                );
                self.discard_oldkey_threshold = None;
                self.crypto.discard_last_key();
            }
        }

        Ok(())
    }

    pub fn next_time(&self) -> Option<u64> {
        let idle_update_threshold = if let Some(ref threshold) = self.idle_timeout_threshold {
            (*threshold - self.current_ts).as_millis() as u64
        } else {
            u64::MAX
        };

        let key_update_threshold = if let Some(ref threshold) = self.discard_oldkey_threshold {
            (*threshold - self.current_ts).as_millis() as u64
        } else {
            u64::MAX
        };

        let timeout = idle_update_threshold.min(key_update_threshold);
        if timeout == 0 {
            None
        } else {
            Some(timeout)
        }
    }

    #[allow(unused_variables)]
    pub fn provide_data(&mut self, rcvbuf: &[u8], source_addr: SocketAddr) -> Result<()> {
        let span = span!(Level::TRACE, "provide data");
        let _enter = span.enter();

        // Update idle timeout threshold
        let idle_timeout = self.get_idle_timeout();
        self.idle_timeout_threshold = if idle_timeout != 0 {
            self.current_ts
                .checked_add(Duration::from_millis(idle_timeout))
        } else {
            None
        };

        QuicPacket::handle_quic_packet(rcvbuf, self, &source_addr).with_context(|| {
            format!(
                "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                self.scid, self.dcid, self.org_dcid
            )
        })?;

        Ok(())
    }

    pub fn consume_data(&mut self) -> Option<Vec<u8>> {
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
        self.expected_state(QuicConnectionState::Init)
            .with_context(|| {
                format!(
                    "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                    self.scid, self.dcid, self.org_dcid
                )
            })?;
        self.state = QuicConnectionState::Connecting;
        let _enter = span.enter();
        QuicPacket::start_tls_handshake(self, false).with_context(|| {
            format!(
                "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                self.scid, self.dcid, self.org_dcid
            )
        })?;

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

    pub(crate) fn set_oldkey_discard_time(&mut self, timeout: u64) {
        self.discard_oldkey_threshold = Instant::now().checked_add(Duration::from_millis(timeout));
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
