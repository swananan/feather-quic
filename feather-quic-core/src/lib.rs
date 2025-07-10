// Re-export commonly used types and functions
pub mod prelude {
    pub use crate::config::{QuicConfig, DEFAULT_INITIAL_PACKET_SIZE};
    pub use crate::connection::{QuicConnectResult, QuicConnection, QuicConnectionError};
    pub use crate::runtime::{QuicCallbacks, QuicRuntime, QuicUserContext, RuntimeConfig};
    pub use crate::stream::{QuicStreamError, QuicStreamHandle};
    pub use crate::transport_parameters::{MAX_UDP_PAYLOAD_SIZE, MIN_UDP_PAYLOAD_SIZE};
    pub use crate::user_api::QuicConnectionInterface;
}

// Internal modules
mod ack;
mod buffer;
pub mod config;
pub mod connection;
mod crypto;
mod error_code;
mod flow_control;
mod frame;
mod migration;
mod mtu_discovery;
mod packet;
mod rtt;
pub mod runtime;
mod send;
pub mod stream;
mod tls;
mod transport_parameters;
pub mod user_api;
mod utils;

// Re-export prelude for convenience
pub use prelude::*;
