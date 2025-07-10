use anyhow::Result;
use std::net::SocketAddr;

pub use crate::connection::QuicConnectionError;
use crate::stream::QuicStreamHandle;

/// Example usage of the QuicConnectionInterface:
///
/// ```rust
/// use feather_quic_core::{
///     QuicConnectionInterface, QuicConnection, QuicConfig, QuicStreamHandle
/// };
/// use std::net::SocketAddr;
///
/// // Create a connection using the constructor
/// let config = QuicConfig::default();
/// let target_addr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
/// let mut connection = QuicConnection::new(config, target_addr);
///
/// // Use the user API methods in callbacks
/// fn handle_read_event<T>(conn: &mut impl QuicConnectionInterface, stream: QuicStreamHandle) {
///     if conn.is_established() {
///         match conn.stream_recv(stream, 1024) {
///             Ok(data) => println!("Received {} bytes", data.len()),
///             Err(e) => eprintln!("Error receiving data: {}", e),
///         }
///     }
/// }
///
/// fn handle_write_event<T>(conn: &mut impl QuicConnectionInterface, stream: QuicStreamHandle) {
///     if conn.is_established() {
///         let data = b"Hello, QUIC!";
///         match conn.stream_send(stream, data) {
///             Ok(sent) => println!("Sent {} bytes", sent),
///             Err(e) => eprintln!("Error sending data: {}", e),
///         }
///     }
/// }
/// ```
/// QUIC Connection Interface
///
/// This trait provides the public interface for QUIC connections that can be used
/// in callback functions. It abstracts away the internal implementation details
/// and provides a clean API for users.
pub trait QuicConnectionInterface {
    /// Check if the connection is established
    fn is_established(&self) -> bool;

    /// Check if the connection is in closing state
    fn is_closing(&self) -> bool;

    /// Check if the connection is closed
    fn is_closed(&self) -> bool;

    /// Check if the connection is in draining state
    fn is_draining(&self) -> bool;

    /// Close the QUIC connection
    ///
    /// # Arguments
    /// * `error_code` - Application error code
    /// * `reason_phrase` - Optional reason phrase for closing
    fn close(
        &mut self,
        error_code: u64,
        reason_phrase: Option<String>,
    ) -> Result<(), QuicConnectionError>;

    /// Open a new QUIC stream
    ///
    /// # Arguments
    /// * `is_bidirectional` - Whether the stream should be bidirectional
    ///
    /// # Returns
    /// * `QuicStreamHandle` - Handle to the newly created stream
    fn open_stream(
        &mut self,
        is_bidirectional: bool,
    ) -> Result<QuicStreamHandle, QuicConnectionError>;

    /// Finish sending data on a stream
    ///
    /// # Arguments
    /// * `stream_handle` - Handle to the stream to finish
    fn stream_finish(&mut self, stream_handle: QuicStreamHandle)
        -> Result<(), QuicConnectionError>;

    /// Shutdown write on a stream with an error code
    ///
    /// # Arguments
    /// * `stream_handle` - Handle to the stream
    /// * `application_error_code` - Application error code for the reset
    fn stream_shutdown_write(
        &mut self,
        stream_handle: QuicStreamHandle,
        application_error_code: u64,
    ) -> Result<(), QuicConnectionError>;

    /// Shutdown read on a stream with an error code
    ///
    /// # Arguments
    /// * `stream_handle` - Handle to the stream
    /// * `application_error_code` - Application error code for the reset
    fn stream_shutdown_read(
        &mut self,
        stream_handle: QuicStreamHandle,
        application_error_code: u64,
    ) -> Result<(), QuicConnectionError>;

    /// Receive data from a stream
    ///
    /// # Arguments
    /// * `stream_handle` - Handle to the stream
    /// * `recv_len` - Maximum number of bytes to receive
    ///
    /// # Returns
    /// * `Vec<u8>` - Received data
    fn stream_recv(
        &mut self,
        stream_handle: QuicStreamHandle,
        recv_len: usize,
    ) -> Result<Vec<u8>, QuicConnectionError>;

    /// Send data to a stream
    ///
    /// # Arguments
    /// * `stream_handle` - Handle to the stream
    /// * `snd_buf` - Data to send
    ///
    /// # Returns
    /// * `usize` - Number of bytes actually sent
    fn stream_send(
        &mut self,
        stream_handle: QuicStreamHandle,
        snd_buf: &[u8],
    ) -> Result<usize, QuicConnectionError>;

    /// Set stream write active state
    ///
    /// # Arguments
    /// * `stream_handle` - Handle to the stream
    /// * `flag` - Whether to activate write
    fn set_stream_write_active(
        &mut self,
        stream_handle: QuicStreamHandle,
        flag: bool,
    ) -> Result<(), QuicConnectionError>;

    /// Set stream read active state
    ///
    /// # Arguments
    /// * `stream_handle` - Handle to the stream
    /// * `flag` - Whether to activate read
    fn set_stream_read_active(
        &mut self,
        stream_handle: QuicStreamHandle,
        flag: bool,
    ) -> Result<(), QuicConnectionError>;

    /// Migrate the connection to a new target address
    ///
    /// This is a client-only API that allows the client to actively migrate
    /// the connection to a different server address. The migration process
    /// involves:
    /// 1. Adding the new address as a potential path
    /// 2. Sending PATH_CHALLENGE frames to validate the new path
    /// 3. Switching to the new path once validated
    ///
    /// # Arguments
    /// * `new_target_address` - The new target server address to migrate to
    ///
    /// # Returns
    /// * `Result<(), QuicConnectionError>` - Success or error
    ///
    /// # Example
    /// ```rust
    /// use std::net::SocketAddr;
    /// use feather_quic_core::{QuicConnection, QuicConfig, QuicConnectionInterface};
    ///
    /// // Create a connection first
    /// let config = QuicConfig::default();
    /// let target_addr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
    /// let mut conn = QuicConnection::new(config, target_addr);
    ///
    /// // Migrate to a new server address
    /// let new_addr = "192.168.1.100:8080".parse::<SocketAddr>().unwrap();
    /// match conn.migrate_to_address(new_addr) {
    ///     Ok(()) => println!("Migration initiated successfully"),
    ///     Err(e) => eprintln!("Migration failed: {}", e),
    /// }
    /// ```
    fn migrate_to_address(
        &mut self,
        new_target_address: SocketAddr,
    ) -> Result<(), QuicConnectionError>;
}

/// Extension trait for QuicConnection to implement the interface
impl QuicConnectionInterface for crate::connection::QuicConnection {
    fn is_established(&self) -> bool {
        self.is_established()
    }

    fn is_closing(&self) -> bool {
        self.is_closing()
    }

    fn is_closed(&self) -> bool {
        self.is_closed()
    }

    fn is_draining(&self) -> bool {
        self.is_draining()
    }

    fn close(
        &mut self,
        error_code: u64,
        reason_phrase: Option<String>,
    ) -> Result<(), QuicConnectionError> {
        self.close_internal(error_code, reason_phrase)
    }

    fn open_stream(
        &mut self,
        is_bidirectional: bool,
    ) -> Result<QuicStreamHandle, QuicConnectionError> {
        self.open_stream_internal(is_bidirectional)
    }

    fn stream_finish(
        &mut self,
        stream_handle: QuicStreamHandle,
    ) -> Result<(), QuicConnectionError> {
        self.stream_finish_internal(stream_handle)
    }

    fn stream_shutdown_write(
        &mut self,
        stream_handle: QuicStreamHandle,
        application_error_code: u64,
    ) -> Result<(), QuicConnectionError> {
        self.stream_shutdown_write_internal(stream_handle, application_error_code)
    }

    fn stream_shutdown_read(
        &mut self,
        stream_handle: QuicStreamHandle,
        application_error_code: u64,
    ) -> Result<(), QuicConnectionError> {
        self.stream_shutdown_read_internal(stream_handle, application_error_code)
    }

    fn stream_recv(
        &mut self,
        stream_handle: QuicStreamHandle,
        recv_len: usize,
    ) -> Result<Vec<u8>, QuicConnectionError> {
        self.stream_recv_internal(stream_handle, recv_len)
    }

    fn stream_send(
        &mut self,
        stream_handle: QuicStreamHandle,
        snd_buf: &[u8],
    ) -> Result<usize, QuicConnectionError> {
        self.stream_send_internal(stream_handle, snd_buf)
    }

    fn set_stream_write_active(
        &mut self,
        stream_handle: QuicStreamHandle,
        flag: bool,
    ) -> Result<(), QuicConnectionError> {
        self.set_stream_write_active_internal(stream_handle, flag)
    }

    fn set_stream_read_active(
        &mut self,
        stream_handle: QuicStreamHandle,
        flag: bool,
    ) -> Result<(), QuicConnectionError> {
        self.set_stream_read_active_internal(stream_handle, flag)
    }

    fn migrate_to_address(
        &mut self,
        new_target_address: SocketAddr,
    ) -> Result<(), QuicConnectionError> {
        self.migrate_to_address_internal(new_target_address)
    }
}
