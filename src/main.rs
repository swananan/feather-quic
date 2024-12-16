use anyhow::{Context, Result};
use clap::Parser;
use log::{info, trace, warn};
use mio::{net::UdpSocket, Events, Interest, Poll, Token};
use mio_timerfd::{ClockId, TimerFd};
use std::io;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "Feather-QUIC-Client")]
#[command(version = "0.1")]
#[command(author = "Zhenzhong Wu <jt26wzz@gmail.com>")]
struct Cli {
    /// Establishes a QUIC connection with the target address as a QUIC client
    #[arg(short, long)]
    target_address: String,

    /// QUIC protocol idle timeout in milliseconds (default: 5000ms)
    #[arg(short, long, default_value_t = 5000)]
    idle_timeout: u64,
}

mod connection;

use crate::connection::{QuicConfig, QuicConnection};

const UDP_SOCKET: Token = Token(0);
const QUIC_TIMER_TOKEN: Token = Token(1);

fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let target_addr = cli
        .target_address
        .parse()
        .with_context(|| format!("Failed to parse target address {} here", cli.target_address))?;

    // Non-blocking mode is enabled by default in mio
    let mut client_socket = UdpSocket::bind("0.0.0.0:0".parse()?)
        .with_context(|| "Failed to bind random address".to_string())?;

    client_socket
        .connect(target_addr)
        .with_context(|| format!("Failed to connect target {:?}", target_addr))?;

    let local_addr = client_socket.local_addr().with_context(|| {
        format!(
            "Failed to get local address from socket {:?}",
            client_socket
        )
    })?;
    info!(
        "UDP socket created successfully - target: {:?}, local: {:?}",
        target_addr, local_addr,
    );

    let mut quic_timer = TimerFd::new(ClockId::Monotonic)?;

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(5);

    info!("Starting QUIC handshake with target: {:?}", target_addr);

    let mut quic_config = QuicConfig::default();

    quic_timer.set_timeout(&Duration::from_millis(cli.idle_timeout))?;
    quic_config.set_idle_timeout(cli.idle_timeout);

    let mut qconn = QuicConnection::new(quic_config);

    //let mut udp_sndbuf = [0; 1 << 16];
    // TODO: Initialize QUIC handshake
    // let initial_packet_size = qconn.connect(&mut udp_sndbuf)?;
    // client_socket.send(&udp_sndbuf[..initial_packet_size as usize])?;

    poll.registry()
        .register(&mut client_socket, UDP_SOCKET, Interest::READABLE)?;
    poll.registry()
        .register(&mut quic_timer, QUIC_TIMER_TOKEN, Interest::READABLE)?;

    // Buffer size set to 65536 (maximum UDP datagram size)
    let mut udp_rcvbuf = [0; 1 << 16];

    loop {
        if let Err(err) = poll.poll(&mut events, None) {
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow::anyhow!("Failed to poll events: {}", err)
                .context("Error occurred during polling"));
        }

        for event in events.iter() {
            match event.token() {
                UDP_SOCKET => loop {
                    match client_socket.recv_from(&mut udp_rcvbuf) {
                        Ok((packet_size, source_addr)) => {
                            trace!("Received {} bytes from {}", packet_size, source_addr);

                            // qconn.update_current_time();

                            // TODO: Process QUIC handshake
                            // qconn.provide_data(&udp_rcvbuf[..packet_size], &source_addr)?;

                            while let Some(send_buf) = qconn.consume_data() {
                                trace!("Sending {} bytes to {}", send_buf.len(), target_addr);
                                client_socket.send(&send_buf)?;
                            }

                            // Update the idle timer
                            // if let Some(timeout) = qconn.next_time() {
                            //     trace!("Update timeout {}ms", timeout);
                            //     quic_timer.set_timeout(&Duration::from_millis(timeout))?;
                            // }

                            // TODO: When QUIC handshake is completed, client can send some data.
                            // like HTTP/3 traffic actually
                            // if qconn.is_established() {
                            // qconn.send(data)?;
                            // }

                            // if qconn.is_readable() {}
                        }
                        Err(err)
                            if err.kind() == io::ErrorKind::WouldBlock
                                || err.kind() == io::ErrorKind::Interrupted =>
                        {
                            break;
                        }
                        Err(err) => {
                            // TODO: Handle QUIC Migration (UDP 4-tuple changes)
                            return Err(anyhow::anyhow!("Socket read failed: {}", err)
                                .context(format!("Error while reading from {:?}", client_socket)));
                        }
                    }
                },
                QUIC_TIMER_TOKEN => {
                    if let Ok(real_timeout) = quic_timer.read() {
                        warn!("QUIC timer triggered {} times!", real_timeout);
                        // TODO: Process QUIC timer events and update as needed
                        // qconn.run_timer()?;
                    }
                }
                _ => {
                    warn!("Received event for unexpected token: {:?}", event);
                }
            }
        }
    }
}
