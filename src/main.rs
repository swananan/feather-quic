use anyhow::{Context, Result};
use clap::{Arg, Command};
use clap_num::number_range;
use std::net::{SocketAddr, ToSocketAddrs};
use tracing::{info, trace};
use tracing_subscriber::EnvFilter;

mod ack;
mod config;
mod connection;
mod crypto;
mod frame;
mod packet;
mod rtt;
mod runtime;
mod send;
mod tls;
mod transport_parameters;
mod utils;

use crate::config::{QuicConfig, DEFAULT_INITIAL_PACKET_SIZE};
use crate::connection::QuicConnection;
use crate::runtime::{QuicCallbacks, QuicRuntime, QuicUserContext, RuntimeConfig};

fn limitation_initial_packet_size(s: &str) -> Result<u16, String> {
    number_range(s, DEFAULT_INITIAL_PACKET_SIZE, u16::MAX)
}

fn more_then_zero(s: &str) -> Result<u64, String> {
    number_range(s, 1, u64::MAX)
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

fn validate_rate(s: &str) -> Result<f32, String> {
    let rate: f32 = s
        .parse()
        .map_err(|_| format!("Invalid float value: {}", s))?;
    if !(0.0..=1.0).contains(&rate) {
        return Err(format!("Rate must be between 0.0 and 1.0, got {}", rate));
    }
    Ok(rate)
}

fn main() -> Result<()> {
    let mut config = QuicConfig::default();

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
                .help("QUIC protocol idle timeout in milliseconds (idle timeout is disabled by default)")
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
                .long("odcid")
                .help("Custom your own QUIC original `Destination Connection ID` (hex string, optional)")
                .value_parser(parse_hex_to_bytes),
        )
        .arg(
            Arg::new("alpn")
                .long("alpn")
                .help("Alpn of QUIC, default value is `h3`")
                .num_args(1),
        )
        .arg(
            Arg::new("server_name")
                .long("sni")
                .help("TLS Server Name Identification of QUIC, default value is target_address")
                .num_args(1),
        )
        .arg(
            Arg::new("ssl_key_log")
                .long("ssl-key-log")
                .help("TLS Server_name of QUIC, default value is target_address")
                .num_args(1),
        )
        .arg(
            Arg::new("initial_max_data")
                .long("initial-max-data")
                .help("Transport Parameter: Maximum data for QUIC connection in bytes (default: 524288)")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("initial_max_stream_data_bidi_local")
                .long("initial-max-stream-data-bidi-local")
                .help("Transport Parameter: Maximum stream data for bidirectional local streams in bytes (default: 65536)")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("initial_max_stream_data_bidi_remote")
                .long("initial-max-stream-data-bidi-remote")
                .help("Transport Parameter: Maximum stream data for bidirectional remote streams in bytes (default: 65536)")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("initial_max_stream_data_uni")
                .long("initial-max-stream-data-uni")
                .help("Transport Parameter: Maximum stream data for unidirectional streams in bytes (default: 65536)")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("initial_max_streams_bidi")
                .long("initial-max-streams-bidi")
                .help("Transport Parameter: Maximum number of concurrent bidirectional streams (default: 100)")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("initial_max_streams_uni")
                .long("initial-max-streams-uni")
                .help("Transport Parameter: Maximum number of concurrent unidirectional streams (default: 100)")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("ack_delay_exponent")
                .long("ack-delay-exponent")
                .help("Transport Parameter: Exponent used to decode ACK Delay field (default: 3)")
                .value_parser(clap::value_parser!(u8)),
        )
        .arg(
            Arg::new("max_ack_delay")
                .long("max-ack-delay")
                .help("Transport Parameter: Maximum amount of time in milliseconds to delay sending acknowledgments (default: 25)")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("disable_active_migration")
                .long("disable-active-migration")
                .help("Transport Parameter: Disable active connection migration (default: false)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("active_connection_id_limit")
                .long("active-connection-id-limit")
                .help("Transport Parameter: Maximum number of connection IDs from peer (default: 7)")
                .value_parser(clap::value_parser!(u8)),
        )
        .arg(
            Arg::new("max_udp_payload_size")
                .long("max-udp-payload-size")
                .help("Transport Parameter: Maximum size of UDP payloads in bytes (default: 65527)")
                .value_parser(clap::value_parser!(u32)),
        )
        .arg(
            Arg::new("trigger_key_update")
                .long("trigger-key-update")
                .help("Specifies the number of packets sent by the client before triggering a key update voluntarily.\
                    The key update will be triggered after the specified number of packets have been sent.\
                    This number is at least 1, since an endpoint MUST NOT initiate a subsequent key update\
                    unless it has received an acknowledgment for a packet that was sent protected with keys from the current key phase.\
                    (default: disabled)")
                .value_parser(more_then_zero),
        )
        .arg(
            Arg::new("max_quic_packet_send_count")
                .long("max-quic-packet-send-count")
                .help("Maximum number of QUIC packets that can be sent by this client. \
                    This is a testing parameter that artificially limits packet transmission. \
                    When the limit is reached, the connection will be closed. \
                    By default, there is no limit.")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("packet_loss_rate")
                .long("loss-rate")
                .help("Packet loss rate (0.0 - 1.0) for both sending and receiving. \
                    Will be overridden by --send-loss-rate or --recv-loss-rate if specified")
                .value_parser(validate_rate),
        )
        .arg(
            Arg::new("send_packet_loss_rate")
                .long("send-loss-rate")
                .help("Packet loss rate (0.0 - 1.0) for sending packets. \
                    Takes precedence over --loss-rate")
                .value_parser(validate_rate),
        )
        .arg(
            Arg::new("recv_packet_loss_rate")
                .long("recv-loss-rate")
                .help("Packet loss rate (0.0 - 1.0) for receiving packets. \
                    Takes precedence over --loss-rate")
                .value_parser(validate_rate),
        )
        .arg(
            Arg::new("packet_reorder_rate")
                .long("reorder-rate")
                .help("Packet reorder rate (0.0 - 1.0) for both sending and receiving. \
                    Will be overridden by --send-reorder-rate or --recv-reorder-rate if specified")
                .value_parser(validate_rate),
        )
        .arg(
            Arg::new("send_packet_reorder_rate")
                .long("send-reorder-rate")
                .help("Packet reorder rate (0.0 - 1.0) for sending packets. \
                    Takes precedence over --reorder-rate")
                .value_parser(validate_rate),
        )
        .arg(
            Arg::new("recv_packet_reorder_rate")
                .long("recv-reorder-rate")
                .help("Packet reorder rate (0.0 - 1.0) for receiving packets. \
                    Takes precedence over --reorder-rate")
                .value_parser(validate_rate),
        )
        .arg(
            Arg::new("reorder_queue_size")
                .long("reorder-queue-size")
                .help("Maximum size of the packet reordering queue (default: 32)")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("reorder_delay_ms")
                .long("reorder-delay")
                .help("Maximum delay in milliseconds for reordered packets (default: 10) Not implemented yet!")
                .value_parser(clap::value_parser!(u64)),
        )
        .get_matches();

    let env_filter = EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let use_io_uring = matches.get_flag("use_io_uring");
    let target_address = matches.get_one::<String>("target_address").unwrap().clone();

    let target_addr: SocketAddr = target_address
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("Invalid target address: {}", target_address))?;

    if let Some(idle_timeout) = matches.get_one::<u64>("idle_timeout") {
        config.set_idle_timeout(*idle_timeout);
    }

    if let Some(first_initial_packet_size) = matches.get_one::<u16>("first_initial_packet_size") {
        config.set_first_initial_packet_size(*first_initial_packet_size);
    }

    if let Some(scid) = matches.get_one::<Vec<u8>>("scid") {
        config.set_scid(scid);
    }

    if let Some(log_file) = matches.get_one::<String>("ssl_key_log") {
        config.set_key_log_file(log_file.clone());
    }

    if let Some(alpn) = matches.get_one::<String>("alpn") {
        config.set_alpn(alpn);
    } else {
        config.set_alpn("h3");
    }

    if let Some(sn) = matches.get_one::<String>("server_name") {
        config.set_server_name(sn);
    } else {
        config.set_server_name(target_address.split(':').next().unwrap_or(&target_address));
    }

    if let Some(original_dcid) = matches.get_one::<Vec<u8>>("original_dcid") {
        config.set_original_dcid(original_dcid);
    }

    if let Some(value) = matches.get_one::<u64>("initial_max_data") {
        config.set_initial_max_data(*value);
    }

    if let Some(value) = matches.get_one::<u64>("initial_max_stream_data_bidi_local") {
        config.set_initial_max_stream_data_bidi_local(*value);
    }

    if let Some(value) = matches.get_one::<u64>("initial_max_stream_data_bidi_remote") {
        config.set_initial_max_stream_data_bidi_remote(*value);
    }

    if let Some(value) = matches.get_one::<u64>("initial_max_stream_data_uni") {
        config.set_initial_max_stream_data_uni(*value);
    }

    if let Some(value) = matches.get_one::<u64>("initial_max_streams_bidi") {
        config.set_initial_max_streams_bidi(*value);
    }

    if let Some(value) = matches.get_one::<u64>("initial_max_streams_uni") {
        config.set_initial_max_streams_uni(*value);
    }

    if let Some(value) = matches.get_one::<u8>("ack_delay_exponent") {
        config.set_ack_delay_exponent(*value);
    }

    if let Some(value) = matches.get_one::<u16>("max_ack_delay") {
        config.set_max_ack_delay(*value);
    }

    if matches.get_flag("disable_active_migration") {
        config.set_disable_active_migration(true);
    }

    if let Some(value) = matches.get_one::<u8>("active_connection_id_limit") {
        config.set_active_connection_id_limit(*value);
    }

    if let Some(value) = matches.get_one::<u32>("max_udp_payload_size") {
        config.set_max_udp_payload_size(*value);
    }

    if let Some(value) = matches.get_one::<u64>("trigger_key_update") {
        config.set_trigger_key_update(*value);
    }

    let max_quic_packet_send_count = matches
        .get_one::<u64>("max_quic_packet_send_count")
        .copied();

    let loss_rate = matches.get_one::<f32>("packet_loss_rate").copied();

    let send_loss_rate = matches
        .get_one::<f32>("send_packet_loss_rate")
        .copied()
        .or(loss_rate);

    let recv_loss_rate = matches
        .get_one::<f32>("recv_packet_loss_rate")
        .copied()
        .or(loss_rate);

    let reorder_rate = matches.get_one::<f32>("packet_reorder_rate").copied();

    let send_reorder_rate = matches
        .get_one::<f32>("send_packet_reorder_rate")
        .copied()
        .or(reorder_rate);

    let recv_reorder_rate = matches
        .get_one::<f32>("recv_packet_reorder_rate")
        .copied()
        .or(reorder_rate);

    /* let reorder_queue_size = matches
        .get_one::<usize>("reorder_queue_size")
        .copied()
        .unwrap_or(32);

    let reorder_delay_ms = matches
        .get_one::<u64>("reorder_delay_ms")
        .copied()
        .unwrap_or(10); */

    let runtime_config = RuntimeConfig {
        use_io_uring,
        max_quic_packet_send_count,
        tx_packet_loss_rate: send_loss_rate,
        rx_packet_loss_rate: recv_loss_rate,
        tx_packet_reorder_rate: send_reorder_rate,
        rx_packet_reorder_rate: recv_reorder_rate,
        io_uring_capacity: 256,
        buffer_size: 1 << 16,
        target_address: target_addr,
    };

    let mut qconn = QuicConnection::new(config);
    let mut uctx = QuicUserContext::new(FeatherQuicClientContext::default());
    let mut runtime = QuicRuntime::new(runtime_config);

    runtime.run(&mut qconn, &mut uctx)?;

    Ok(())
}
