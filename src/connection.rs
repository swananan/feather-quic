use anyhow::Result;
use std::time::Instant;

pub struct QuicConnection {
    quic_config: QuicConfig,
    current_ts: Instant,
}

#[allow(dead_code)]
impl QuicConnection {
    pub fn new(quic_config: QuicConfig) -> Self {
        QuicConnection {
            quic_config,
            current_ts: Instant::now(),
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
        self.update_current_time();
        Ok(())
    }

    pub fn next_time(&self) -> Option<u64> {
        Some(self.get_idle_timeout())
    }

    #[allow(unused_variables)]
    pub fn provide_data(&mut self, rcvbuf: &[u8]) -> Result<()> {
        unimplemented!();
    }

    pub fn consume_data(&mut self) -> Option<Vec<u8>> {
        unimplemented!();
    }

    #[allow(unused_variables)]
    pub fn connect(&mut self, sndbuf: &mut [u8]) -> Result<u16> {
        unimplemented!();
    }

    pub fn get_idle_timeout(&self) -> u64 {
        // TODO: Retrieve idle timeout from server transport parameters
        self.quic_config.get_idle_timeout()
    }
}

#[derive(Clone, Default)]
pub struct QuicConfig {
    idle_timeout: u64,
}

impl QuicConfig {
    pub fn set_idle_timeout(&mut self, idle_timeout: u64) {
        self.idle_timeout = idle_timeout;
    }

    pub fn get_idle_timeout(&self) -> u64 {
        self.idle_timeout
    }
}
