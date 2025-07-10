use crate::connection::QuicConnectResult;
use crate::connection::QuicConnection;
use crate::stream::QuicStreamHandle;

use anyhow::Result;
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
mod io_uring;
mod mio;
mod socket_utils;

#[cfg(target_os = "linux")]
pub(crate) use io_uring::IoUringEventLoop;
pub(crate) use mio::MioEventLoop;

pub use crate::migration::MigrationResult;

pub struct QuicUserContext<T: QuicCallbacks> {
    pub callbacks: T,
}

impl<T: QuicCallbacks> QuicUserContext<T> {
    pub fn new(callbacks: T) -> Self {
        Self { callbacks }
    }

    pub(crate) fn run_connect_done_event(
        &mut self,
        qconn: &mut QuicConnection,
        result: QuicConnectResult,
    ) -> Result<()> {
        self.callbacks.connect_done(qconn, result)
    }

    pub(crate) fn run_close_event(
        &mut self,
        qconn: &mut QuicConnection,
        error_code: Option<u64>,
        reason: Option<String>,
    ) -> Result<()> {
        self.callbacks.close(qconn, error_code, reason)
    }

    pub(crate) fn run_read_event(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()> {
        self.callbacks.read_event(qconn, stream_handle)
    }

    pub(crate) fn run_write_event(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()> {
        self.callbacks.write_event(qconn, stream_handle)
    }

    pub(crate) fn run_migration_switch_result_event(
        &mut self,
        qconn: &mut QuicConnection,
        old_path_id: u64,
        new_path_id: u64,
        result: MigrationResult,
    ) -> Result<()> {
        self.callbacks
            .migration_switch_result(qconn, old_path_id, new_path_id, result)
    }
}

pub trait QuicCallbacks {
    /// Called when connection establishment completes, either successfully or with an error.
    ///
    /// # Parameters
    /// * `qconn` - The QUIC connection object
    /// * `result` - The connection result:
    ///   - `QuicConnectResult::Success` - Connection established successfully
    ///   - `QuicConnectResult::Timeout` - Connection timed out after specified duration
    ///   - `QuicConnectResult::Failed` - Connection failed with error message
    ///
    /// # Returns
    /// `Result<()>` indicating if the callback completed successfully
    fn connect_done(&mut self, qconn: &mut QuicConnection, result: QuicConnectResult)
        -> Result<()>;

    /// Called when a stream is opened by the peer, has data available to read,
    /// or is closed by the peer for reading.
    ///
    /// # Parameters
    /// * `qconn` - The QUIC connection object
    /// * `stream_handle` - Handle identifying the affected stream
    ///
    /// # Returns
    /// `Result<()>` indicating if the callback completed successfully
    fn read_event(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()>;

    /// Called when a stream is ready for writing data,
    /// or is closed by the peer for writing.
    ///
    /// # Parameters
    /// * `qconn` - The QUIC connection object
    /// * `stream_handle` - Handle identifying the stream to write to
    ///
    fn write_event(
        &mut self,
        qconn: &mut QuicConnection,
        stream_handle: QuicStreamHandle,
    ) -> Result<()>;

    /// Called when the connection is closed by the peer or due to idle timeout.
    ///
    /// # Parameters
    /// * `error_code` - Optional error code provided by peer
    /// * `reason` - Optional reason string provided by peer
    fn close(
        &mut self,
        qconn: &mut QuicConnection,
        error_code: Option<u64>,
        reason: Option<String>,
    ) -> Result<()>;

    /// Called when migration switch is completed (success or failure).
    ///
    /// # Parameters
    /// * `qconn` - The QUIC connection object
    /// * `old_path_id` - The old path id before switch
    /// * `new_path_id` - The new path id after switch
    /// * `result` - MigrationResult
    fn migration_switch_result(
        &mut self,
        qconn: &mut QuicConnection,
        old_path_id: u64,
        new_path_id: u64,
        result: MigrationResult,
    ) -> Result<()>;
}

pub enum QuicRuntimeCore {
    Mio(MioEventLoop),
    #[cfg(target_os = "linux")]
    IoUring(IoUringEventLoop),
}

pub struct QuicRuntime {
    core: QuicRuntimeCore,
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub target_address: SocketAddr,
    pub use_io_uring: bool,
    pub io_uring_capacity: usize,
    pub buffer_size: usize,
    pub max_quic_packet_send_count: Option<u64>,
    pub tx_packet_loss_rate: Option<f32>,
    pub rx_packet_loss_rate: Option<f32>,
    pub tx_packet_reorder_rate: Option<f32>,
    pub rx_packet_reorder_rate: Option<f32>,
    pub drop_packets_above_size: Option<u16>,
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
            drop_packets_above_size: None,
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
                config.drop_packets_above_size,
            ))
        } else {
            #[cfg(target_os = "linux")]
            {
                QuicRuntimeCore::IoUring(IoUringEventLoop::with_capacity(
                    config.io_uring_capacity,
                    config.buffer_size,
                    config.target_address,
                    config.max_quic_packet_send_count,
                    config.tx_packet_loss_rate,
                    config.rx_packet_loss_rate,
                    config.drop_packets_above_size,
                ))
            }
            #[cfg(not(target_os = "linux"))]
            {
                panic!("io_uring is only supported on Linux platforms");
            }
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
            #[cfg(target_os = "linux")]
            QuicRuntimeCore::IoUring(ref mut event_loop) => event_loop.run(qconn, uctx)?,
        }

        Ok(())
    }
}
