use anyhow::{Context, Result};
use clap::{Arg, Command};
use clap_num::number_range;
use std::net::SocketAddr;
use tracing::{info, trace};
use tracing_subscriber::EnvFilter;

mod connection;
mod crypto;
mod frame;
mod packet;
mod runtime;
mod send;
mod tls;
mod utils;

use crate::connection::{QuicConfig, QuicConnection};
use crate::packet::DEFAULT_INITIAL_PACKET_SIZE;
use crate::runtime::{QuicCallbacks, QuicRuntime, QuicUserContext};

fn limitation_initial_packet_size(s: &str) -> Result<u16, String> {
    number_range(s, DEFAULT_INITIAL_PACKET_SIZE, u16::MAX)
}

fn parse_hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!(
            "Hex string '{}' must have an even number of characters.",
            hex
        ));
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex character in '{}'.", &hex[i..i + 2]))
        })
        .collect()
}

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
    let matches = Command::new("Feather QUIC Client")
        .version("0.0.2")
        .author("Zhenzhong Wu <jt26wzz@gmail.com>")
        .arg(
            Arg::new("target_address")
                .short('t')
                .long("target-address")
                .help("Target address to establish QUIC connection with")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("idle_timeout")
                .short('i')
                .long("idle-timeout")
                .help("QUIC protocol idle timeout in milliseconds (default: 5000ms)")
                .default_value("5000")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("use_io_uring")
                .long("use-io-uring")
                .help("Use io-uring-based QUIC runtime instead of default Mio Epoll")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("first_initial_packet_size_with_limits")
                .long("first-initial-packet-size-with-limits")
                .help("First QUIC initial packet size in bytes (default: 1200, range [1200, 65536])")
                .default_value("1200")
                .value_parser(limitation_initial_packet_size),
        )
        .arg(
            Arg::new("first_initial_packet_size")
                .long("first-initial-packet-size")
                .help("First QUIC initial packet size in bytes (default: 1200, range [0, 65536])")
                .default_value("1200")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("scid")
                .long("scid")
                .help("Custom your own QUIC `Source Connection ID` (hex string, optional)")
                .value_parser(parse_hex_to_bytes),
        )
        .arg(
            Arg::new("original_dcid")
                .long("original-dcid")
                .help("Custom your own QUIC original `Destination Connection ID` (hex string, optional)")
                .value_parser(parse_hex_to_bytes),
        )
        .get_matches();

    let env_filter = EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let use_io_uring = matches.get_flag("use_io_uring");
    let target_address = matches.get_one::<String>("target_address").unwrap().clone();
    let idle_timeout = *matches.get_one::<u64>("idle_timeout").unwrap();
    let first_initial_packet_size = *matches.get_one::<u16>("first_initial_packet_size").unwrap();

    let target_addr: SocketAddr = target_address
        .parse()
        .with_context(|| format!("Invalid target address: {}", target_address))?;

    let mut quic_config = QuicConfig::default();

    quic_config.set_idle_timeout(idle_timeout);
    quic_config.set_first_initial_packet_size(first_initial_packet_size);
    if let Some(scid) = matches.get_one::<Vec<u8>>("scid") {
        quic_config.set_scid(scid);
    }

    if let Some(original_dcid) = matches.get_one::<Vec<u8>>("original_dcid") {
        quic_config.set_original_dcid(original_dcid);
    }

    let mut qconn = QuicConnection::new(quic_config);

    let mut runtime = QuicRuntime::new(use_io_uring, target_addr);
    let mut uctx = QuicUserContext::new(FeatherQuicClientContext::default());

    runtime.run(&mut qconn, &mut uctx)?;

    Ok(())
}
