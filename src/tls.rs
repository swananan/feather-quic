use anyhow::{anyhow, Result};
use std::collections::VecDeque;

use crate::connection::{QuicConfig, QuicLevel};

// QUIC initial phase use this algorithm
pub(crate) const TLS_AES_128_GCM_SHA256: u16 = 0x1301;

pub(crate) const TLS_AES_256_GCM_SHA384: u16 = 0x1302;

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
struct TlsConfig {
    server_name: String,
    alpn: String,
}

#[allow(dead_code)]
impl TlsConfig {
    pub fn new(server_name: String, alpn: String) -> Self {
        Self { server_name, alpn }
    }
}

#[allow(dead_code)]
pub(crate) struct TlsContext {
    tls_config: TlsConfig,

    selected_chipher_suite: Option<u16>,
    send_queue: VecDeque<(Vec<u8>, QuicLevel)>,
}

impl TlsContext {
    #[allow(unused_variables)]
    pub(crate) fn new(quic_config: &QuicConfig, scid: &[u8]) -> Self {
        Self {
            tls_config: TlsConfig::default(),
            selected_chipher_suite: None,
            send_queue: VecDeque::new(),
        }
    }

    pub(crate) fn start_tls_handshake(&mut self) -> Result<()> {
        let client_hello = self.create_client_hello_message()?;
        self.send_queue
            .push_back((client_hello, QuicLevel::Initial));
        Ok(())
    }

    #[allow(unused_variables)]
    pub(crate) fn continue_tls_handshake(
        &mut self,
        crypto_buffer: &[u8],
        length: u64,
    ) -> Result<()> {
        unimplemented!();
    }

    fn create_client_hello_message(&mut self) -> Result<Vec<u8>> {
        // TODO: Temporarily use a placeholder ClientHello message to simulate QUIC handshake initiation.
        let client_hello = vec![0u8; 250];

        Ok(client_hello)
    }

    pub(crate) fn get_selected_cipher_suite(&self) -> Result<u16> {
        self.selected_chipher_suite
            .ok_or_else(|| anyhow!("No cipher suite selected"))
    }

    pub(crate) fn should_send_tls(&self) -> bool {
        !self.send_queue.is_empty()
    }

    pub(crate) fn send(&mut self) -> Option<(Vec<u8>, QuicLevel)> {
        self.send_queue.pop_front()
    }
}
