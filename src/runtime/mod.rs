use crate::runtime::io_uring::IoUringEventLoop;
use crate::runtime::mio::MioEventLoop;
use crate::QuicConnection;

use anyhow::Result;
use std::net::SocketAddr;

mod io_uring;
mod mio;

pub struct QuicUserContext<T> {
    user_data: T,
}

impl<T> QuicUserContext<T> {
    pub fn new(user_data: T) -> Self {
        Self { user_data }
    }
}

pub trait QuicCallbacks {
    fn connect_done(&mut self, qconn: &mut QuicConnection) -> Result<()>;
    fn read_event(&mut self, qconn: &mut QuicConnection) -> Result<()>;
    fn write_event(&mut self, qconn: &mut QuicConnection) -> Result<()>;
    fn close(&mut self, qconn: &mut QuicConnection) -> Result<()>;
}

pub enum QuicRuntimeCore {
    Mio(MioEventLoop),
    IoUring(IoUringEventLoop),
}

pub struct QuicRuntime {
    core: QuicRuntimeCore,
}

pub struct RuntimeConfig {
    pub use_io_uring: bool,
    pub target_address: SocketAddr,
    pub max_quic_packet_send_count: Option<u64>,
    pub tx_packet_loss_rate: Option<f32>,
    pub rx_packet_loss_rate: Option<f32>,
    pub tx_packet_reorder_rate: Option<f32>,
    pub rx_packet_reorder_rate: Option<f32>,
    pub io_uring_capacity: usize,
    pub buffer_size: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            use_io_uring: false,
            target_address: "127.0.0.1:0".parse().unwrap(),
            max_quic_packet_send_count: None,
            tx_packet_loss_rate: None,
            rx_packet_loss_rate: None,
            tx_packet_reorder_rate: None,
            rx_packet_reorder_rate: None,
            io_uring_capacity: 256,
            buffer_size: 1 << 16,
        }
    }
}

impl QuicRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        let core = if !config.use_io_uring {
            QuicRuntimeCore::Mio(MioEventLoop::new(
                config.target_address,
                config.max_quic_packet_send_count,
                config.tx_packet_loss_rate,
                config.rx_packet_loss_rate,
                config.tx_packet_reorder_rate,
                config.rx_packet_reorder_rate,
            ))
        } else {
            QuicRuntimeCore::IoUring(IoUringEventLoop::with_capacity(
                config.io_uring_capacity,
                config.buffer_size,
                config.target_address,
                config.max_quic_packet_send_count,
                config.tx_packet_loss_rate,
                config.rx_packet_loss_rate,
            ))
        };

        Self { core }
    }

    pub fn run<T>(
        &mut self,
        qconn: &mut QuicConnection,
        uctx: &mut QuicUserContext<T>,
    ) -> Result<()>
    where
        T: QuicCallbacks,
    {
        match self.core {
            QuicRuntimeCore::Mio(ref mut event_loop) => event_loop.run(qconn, uctx)?,
            QuicRuntimeCore::IoUring(ref mut event_loop) => event_loop.run(qconn, uctx)?,
        }

        Ok(())
    }
}
