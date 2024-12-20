use anyhow::{Context, Result};
use clap::Parser;
use log::{info, trace};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "Feather-QUIC-Client")]
#[command(version = "0.1")]
#[command(author = "Zhenzhong Wu <jt26wzz@gmail.com>")]
struct Cli {
    /// Use IO_uring-based QUIC runtime instead of default Mio Epoll
    #[arg(long)]
    use_io_uring: bool,

    /// Target address to establish QUIC connection with
    #[arg(short, long)]
    target_address: String,

    /// QUIC protocol idle timeout in milliseconds (default: 5000ms)
    #[arg(short, long, default_value_t = 5000)]
    idle_timeout: u64,
}

mod connection;
mod runtime;

use crate::connection::{QuicConfig, QuicConnection};
use crate::runtime::{QuicCallbacks, QuicRuntime, QuicUserContext};

#[allow(dead_code)]
#[derive(Default)]
struct FeatherQuicClientContext {
    // TODO: Support HTTP/3
    sent_bytes: u64,
    recv_bytes: u64,
}

#[allow(unused_variables)]
impl QuicCallbacks for FeatherQuicClientContext {
    fn close(&mut self, qconn: &mut QuicConnection) -> Result<()> {
        info!("QUIC connection closed");
        Ok(())
    }

    fn connect_done(&mut self, qconn: &mut QuicConnection) -> Result<()> {
        info!("QUIC connection established successfully");
        // TODO: Initiate application data transfer (e.g., HTTP/3)
        Ok(())
    }

    fn read_event(&mut self, qconn: &mut QuicConnection) -> Result<()> {
        trace!("QUIC stream readable event received");
        // TODO: Handle incoming stream data from QUIC stack
        // TODO: Optionally send response data
        Ok(())
    }

    fn write_event(&mut self, qconn: &mut QuicConnection) -> Result<()> {
        trace!("QUIC stream writable event received");
        // TODO: Resume sending data if previously blocked since QUIC stack send queue is full
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let target_addr: SocketAddr = cli
        .target_address
        .parse()
        .with_context(|| format!("Invalid target address: {}", cli.target_address))?;

    let mut quic_config = QuicConfig::default();

    quic_config.set_idle_timeout(cli.idle_timeout);

    let mut qconn = QuicConnection::new(quic_config);

    let mut runtime = QuicRuntime::new(cli.use_io_uring, target_addr);
    let mut uctx = QuicUserContext::new(FeatherQuicClientContext::default());

    runtime.run(&mut qconn, &mut uctx)?;

    Ok(())
}
