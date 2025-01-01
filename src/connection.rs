use anyhow::{Context, Result};
use rand::Rng;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{span, warn, Level};

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

pub struct QuicConnection {
    pub(crate) quic_config: QuicConfig,
    current_ts: Instant,
    idle_timeout_threshold: Option<Instant>,

    pub(crate) scid: Vec<u8>,
    pub(crate) org_dcid: Vec<u8>,
    pub(crate) dcid: Option<Vec<u8>>,
    pub(crate) crypto: QuicCrypto,
    pub(crate) tls: TlsContext,
    pub(crate) retry_token: Option<Vec<u8>>,

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
        let threshold = if quic_config.idle_timeout != 0 {
            now.checked_add(Duration::from_millis(quic_config.idle_timeout))
        } else {
            None
        };

        QuicConnection {
            crypto: QuicCrypto::default(),
            tls: TlsContext::new(&quic_config, &scid),
            current_ts: now,
            idle_timeout_threshold: threshold,
            scid,
            dcid: None,
            retry_token: None,
            org_dcid,
            quic_config,

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
        false
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

        Ok(())
    }

    pub fn next_time(&self) -> Option<u64> {
        Some(self.get_idle_timeout())
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
        let _enter = span.enter();
        QuicPacket::start_tls_handshake(self, false).with_context(|| {
            format!(
                "Quic connection scid {:x?}, dcid {:x?}, org dcid {:x?}",
                self.scid, self.dcid, self.org_dcid
            )
        })?;

        Ok(())
    }

    pub fn get_idle_timeout(&self) -> u64 {
        // TODO: Negotiate idle timeout from server transport parameters
        self.quic_config.idle_timeout
    }

    pub(crate) fn consume_tls_send_queue(&mut self) -> Result<()> {
        if self.tls.should_send_tls() {
            while let Some((buf, level)) = self.tls.send() {
                let send_ctx = match level {
                    QuicLevel::Initial => &mut self.init_send,
                    QuicLevel::Handshake => &mut self.hs_send,
                    QuicLevel::Application => &mut self.app_send,
                };
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
}

#[derive(Clone, Default)]
pub struct QuicConfig {
    pub(crate) idle_timeout: u64,
    pub(crate) first_initial_packet_size: u16,
    pub(crate) org_dcid: Option<Vec<u8>>,
    pub(crate) scid: Option<Vec<u8>>,
}

impl QuicConfig {
    pub fn set_first_initial_packet_size(&mut self, first_initial_packet_size: u16) {
        self.first_initial_packet_size = first_initial_packet_size;
    }

    pub fn set_idle_timeout(&mut self, idle_timeout: u64) {
        self.idle_timeout = idle_timeout;
    }

    pub fn set_original_dcid(&mut self, original_dcid: &[u8]) {
        self.org_dcid = Some(original_dcid.to_owned());
    }

    pub fn set_scid(&mut self, scid: &[u8]) {
        self.scid = Some(scid.to_owned());
    }
}
