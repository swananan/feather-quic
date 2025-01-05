use anyhow::{Context, Result};
use mio::{net::UdpSocket, Events, Interest, Poll, Token};
use mio_timerfd::{ClockId, TimerFd};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, trace, warn};

use crate::runtime::{QuicCallbacks, QuicUserContext};
use crate::QuicConnection;

pub(crate) struct MioEventLoop {
    target_address: SocketAddr,
}

impl MioEventLoop {
    pub fn new(target_address: SocketAddr) -> Self {
        Self { target_address }
    }

    fn create_client_socket(&self) -> Result<UdpSocket> {
        let client_socket = UdpSocket::bind("0.0.0.0:0".parse()?)
            .with_context(|| "Failed to bind random address".to_string())?;

        client_socket
            .connect(self.target_address)
            .with_context(|| format!("Failed to connect target {:?}", self.target_address))?;

        // No need to set non-blocking mode since Mio has already handled it
        let local_addr = client_socket.local_addr().with_context(|| {
            format!(
                "Failed to get local address from Mio socket {:?}",
                client_socket
            )
        })?;
        info!(
            "UDP socket created successfully - target: {:?}, local: {:?}",
            self.target_address, local_addr,
        );

        Ok(client_socket)
    }

    pub fn run<T>(
        &mut self,
        qconn: &mut QuicConnection,
        uctx: &mut QuicUserContext<T>,
    ) -> Result<()>
    where
        T: QuicCallbacks,
    {
        const UDP_SOCKET: Token = Token(0);
        const QUIC_TIMER_TOKEN: Token = Token(1);

        let mut quic_timer = TimerFd::new(ClockId::Monotonic)?;
        let mut poll = Poll::new()?;
        let mut events = Events::with_capacity(5);

        if let Some(timeout) = qconn.next_time() {
            trace!("Update timeout {}ms firstly", timeout);
            quic_timer.set_timeout(&Duration::from_millis(timeout))?;
        }
        let mut client_socket = self.create_client_socket()?;

        poll.registry()
            .register(&mut client_socket, UDP_SOCKET, Interest::READABLE)?;
        poll.registry()
            .register(&mut quic_timer, QUIC_TIMER_TOKEN, Interest::READABLE)?;

        // TODO: Initialize QUIC handshake and send the initial packet
        qconn.connect()?;
        let udp_sndbuf = qconn
            .consume_data()
            .expect("Should have first initial QUIC packet");
        client_socket.send(&udp_sndbuf)?;
        info!(
            "Initiating QUIC handshake, first UDP Datagram size {}",
            udp_sndbuf.len()
        );

        // Buffer size set to 65536 (maximum UDP datagram size)
        let mut udp_rcvbuf = [0; 1 << 16];
        let mut connect_done_trigger = false;

        loop {
            if let Err(err) = poll.poll(&mut events, None) {
                if err.kind() == std::io::ErrorKind::Interrupted {
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

                                qconn.update_current_time();

                                qconn.provide_data(&udp_rcvbuf[..packet_size], source_addr)?;

                                while let Some(send_buf) = qconn.consume_data() {
                                    trace!(
                                        "Sending {} bytes to {}",
                                        send_buf.len(),
                                        self.target_address
                                    );
                                    client_socket.send(&send_buf)?;
                                }

                                // Update the idle timer
                                if let Some(timeout) = qconn.next_time() {
                                    trace!("Update timeout {}ms", timeout);
                                    quic_timer.set_timeout(&Duration::from_millis(timeout))?;
                                }

                                // TODO: After QUIC handshake completion, the client can send application data
                                // (e.g., HTTP/3 traffic)
                                if qconn.is_established() && !connect_done_trigger {
                                    connect_done_trigger = true;
                                    uctx.user_data.connect_done(qconn)?;
                                }

                                if qconn.is_readable() {
                                    uctx.user_data.read_event(qconn)?;
                                }

                                if qconn.is_writable() {
                                    uctx.user_data.write_event(qconn)?;
                                }
                            }
                            Err(err)
                                if err.kind() == std::io::ErrorKind::WouldBlock
                                    || err.kind() == std::io::ErrorKind::Interrupted =>
                            {
                                break;
                            }
                            Err(err) => {
                                // TODO: Handle QUIC connection migration (when UDP 4-tuple changes)
                                uctx.user_data.close(qconn)?;
                                return Err(anyhow::anyhow!("Socket read failed: {}", err)
                                    .context(format!(
                                        "Error while reading from {:?}",
                                        client_socket
                                    )));
                            }
                        }
                    },
                    QUIC_TIMER_TOKEN => {
                        if let Ok(real_timeout) = quic_timer.read() {
                            warn!("Timer event triggered {} times!", real_timeout);
                            qconn.run_timer()?;
                            if let Some(timeout) = qconn.next_time() {
                                trace!("Update timeout {}ms", timeout);
                                quic_timer.set_timeout(&Duration::from_millis(timeout))?;
                            }
                        }
                    }
                    _ => {
                        warn!("Received event for unhandled token: {:?}", event);
                    }
                }
            }
        }
    }
}
