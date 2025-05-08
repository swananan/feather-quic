use crate::runtime::QuicUserContext;
use crate::QuicCallbacks;
use crate::QuicConnection;
use anyhow::{Context, Result};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
#[cfg(target_os = "linux")]
use mio_timerfd::{ClockId, TimerFd};
use rand::Rng;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, trace, warn};

pub struct MioEventLoop {
    sent_cnt: u64,
    target_address: SocketAddr,
    max_quic_packet_send_count: Option<u64>,
    tx_packet_loss_rate: Option<f32>,
    rx_packet_loss_rate: Option<f32>,
    tx_packet_reorder_rate: Option<f32>,
    rx_packet_reorder_rate: Option<f32>,
    tx_reorder_queue: VecDeque<Vec<u8>>,
    rx_reorder_queue: VecDeque<(Vec<u8>, SocketAddr)>,
    rng: rand::rngs::ThreadRng,
    #[cfg(target_os = "linux")]
    quic_timer: Option<TimerFd>,
    #[cfg(not(target_os = "linux"))]
    next_timeout: Option<Duration>,
}

impl MioEventLoop {
    pub fn new(
        target_address: SocketAddr,
        max_quic_packet_send_count: Option<u64>,
        tx_packet_loss_rate: Option<f32>,
        rx_packet_loss_rate: Option<f32>,
        tx_packet_reorder_rate: Option<f32>,
        rx_packet_reorder_rate: Option<f32>,
    ) -> Self {
        Self {
            sent_cnt: 0,
            target_address,
            max_quic_packet_send_count,
            tx_packet_loss_rate,
            rx_packet_loss_rate,
            tx_packet_reorder_rate,
            rx_packet_reorder_rate,
            tx_reorder_queue: VecDeque::new(),
            rx_reorder_queue: VecDeque::new(),
            rng: rand::thread_rng(),
            #[cfg(target_os = "linux")]
            quic_timer: None,
            #[cfg(not(target_os = "linux"))]
            next_timeout: None,
        }
    }

    fn should_drop_tx_packet(&mut self) -> bool {
        if let Some(packet_loss_rate) = self.tx_packet_loss_rate {
            self.rng.gen::<f32>() < packet_loss_rate
        } else {
            false
        }
    }

    fn should_drop_rx_packet(&mut self) -> bool {
        if let Some(packet_loss_rate) = self.rx_packet_loss_rate {
            self.rng.gen::<f32>() < packet_loss_rate
        } else {
            false
        }
    }

    fn should_reorder_tx_packet(&mut self) -> bool {
        if let Some(packet_reorder_rate) = self.tx_packet_reorder_rate {
            self.rng.gen::<f32>() < packet_reorder_rate
        } else {
            false
        }
    }

    fn should_reorder_rx_packet(&mut self) -> bool {
        if let Some(packet_reorder_rate) = self.rx_packet_reorder_rate {
            self.rng.gen::<f32>() < packet_reorder_rate
        } else {
            false
        }
    }

    fn create_client_socket(&self) -> Result<UdpSocket> {
        let client_socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>()?)
            .with_context(|| "Failed to bind random address".to_string())?;

        client_socket
            .connect(self.target_address)
            .with_context(|| format!("Failed to connect target {:?}", self.target_address))?;

        // No need to set non-blocking mode since Mio has already handled it
        Ok(client_socket)
    }

    fn socket_send(&mut self, client_socket: &mut UdpSocket, snd_buf: &[u8]) -> Result<()> {
        if let Some(limit) = self.max_quic_packet_send_count {
            if self.sent_cnt >= limit {
                trace!(
                    "Dropping {} bytes, since the number of sent packets reach the limitation {}",
                    snd_buf.len(),
                    limit
                );
                return Ok(());
            }
        }

        if self.should_drop_tx_packet() {
            trace!(
                "Simulating TX packet loss - dropping {} bytes",
                snd_buf.len()
            );
            self.sent_cnt += 1;
            return Ok(());
        }

        if self.should_reorder_tx_packet() {
            trace!("Queuing TX packet for reordering - {} bytes", snd_buf.len());
            self.tx_reorder_queue.push_back(snd_buf.to_vec());

            if !self.tx_reorder_queue.is_empty() && self.rng.gen::<f32>() < 0.5 {
                if let Some(delayed_packet) = self.tx_reorder_queue.pop_front() {
                    client_socket.send(&delayed_packet)?;
                    trace!(
                        "Sending reordered TX packet - {} bytes",
                        delayed_packet.len()
                    );
                }
            }
        } else {
            client_socket.send(snd_buf)?;
            trace!("Sending {} bytes to {}", snd_buf.len(), self.target_address);
        }

        self.sent_cnt += 1;
        Ok(())
    }

    fn handle_received_packet(
        &mut self,
        qconn: &mut QuicConnection,
        packet_data: &[u8],
        source_addr: SocketAddr,
    ) -> Result<()> {
        if self.should_drop_rx_packet() {
            trace!(
                "Simulating RX packet loss - dropping {} bytes",
                packet_data.len()
            );
            return Ok(());
        }

        if self.should_reorder_rx_packet() {
            trace!(
                "Queuing RX packet for reordering - {} bytes",
                packet_data.len()
            );
            self.rx_reorder_queue
                .push_back((packet_data.to_vec(), source_addr));

            if !self.rx_reorder_queue.is_empty() && self.rng.gen::<f32>() < 0.5 {
                if let Some((delayed_packet, addr)) = self.rx_reorder_queue.pop_front() {
                    qconn.provide_data(&delayed_packet, addr)?;
                    trace!(
                        "Processing reordered RX packet - {} bytes",
                        delayed_packet.len()
                    );
                }
            }
        } else {
            qconn.provide_data(packet_data, source_addr)?;
            trace!(
                "Processing {} bytes from {}",
                packet_data.len(),
                source_addr
            );
        }

        Ok(())
    }

    fn flush_tx_reorder_queue(&mut self, client_socket: &mut UdpSocket) -> Result<()> {
        while let Some(packet) = self.tx_reorder_queue.pop_front() {
            client_socket.send(&packet)?;
            trace!("Flushing reordered TX packet - {} bytes", packet.len());
        }
        Ok(())
    }

    fn flush_rx_reorder_queue(&mut self, qconn: &mut QuicConnection) -> Result<()> {
        while let Some((packet, addr)) = self.rx_reorder_queue.pop_front() {
            qconn.provide_data(&packet, addr)?;
            trace!("Flushing reordered RX packet - {} bytes", packet.len());
        }
        Ok(())
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
        #[cfg(target_os = "linux")]
        const QUIC_TIMER_TOKEN: Token = Token(1);

        let mut poll = Poll::new()?;
        let mut events = Events::with_capacity(5);

        #[cfg(target_os = "linux")]
        {
            let mut quic_timer = TimerFd::new(ClockId::Monotonic)?;
            if let Some(timeout) = qconn.next_time() {
                trace!("Update timeout {}ns firstly", timeout);
                quic_timer.set_timeout(&Duration::from_micros(timeout))?;
            }
            self.quic_timer = Some(quic_timer);
        }

        let mut client_socket = self.create_client_socket()?;

        let local_addr = client_socket.local_addr().with_context(|| {
            format!(
                "Failed to get local address from Mio socket {:?}",
                client_socket
            )
        })?;
        let _span = tracing::span!(
            tracing::Level::TRACE,
            "udp",
            local=?format!("{}:{}", local_addr.ip(), local_addr.port()),
            peer=?format!("{}:{}", self.target_address.ip(), self.target_address.port())
        )
        .entered();

        poll.registry()
            .register(&mut client_socket, UDP_SOCKET, Interest::READABLE)?;
        
        #[cfg(target_os = "linux")]
        {
            if let Some(ref mut timer) = self.quic_timer {
                poll.registry()
                    .register(timer, QUIC_TIMER_TOKEN, Interest::READABLE)?;
            }
        }

        qconn.connect()?;
        let udp_sndbuf = qconn
            .consume_data()
            .expect("Should have first initial QUIC packet");
        self.socket_send(&mut client_socket, &udp_sndbuf)?;
        info!(
            "Initiating QUIC handshake, first UDP Datagram size {}",
            udp_sndbuf.len()
        );

        #[cfg(target_os = "linux")]
        {
            if let Some(timeout) = qconn.next_time() {
                trace!("Update timeout to {}ns", timeout);
                if let Some(ref mut timer) = self.quic_timer {
                    timer.set_timeout(&Duration::from_micros(timeout))?;
                }
            } else {
                warn!("Should not trigger the timer process immediately!");
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            if let Some(timeout) = qconn.next_time() {
                self.next_timeout = Some(Duration::from_micros(timeout));
            }
        }

        // Buffer size set to 65536 (maximum UDP datagram size)
        let mut udp_rcvbuf = [0; 1 << 16];

        loop {
            #[cfg(target_os = "linux")]
            let poll_timeout = None;
            
            #[cfg(not(target_os = "linux"))]
            let poll_timeout = self.next_timeout;

            if let Err(err) = poll.poll(&mut events, poll_timeout) {
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow::anyhow!("Failed to poll events: {}", err)
                    .context("Error occurred during polling"));
            }

            qconn.update_current_time();
            #[cfg(not(target_os = "linux"))]
            {
                // Check if we hit the timeout
                if events.is_empty() {
                    trace!("Timer event triggered via poll timeout");
                    qconn.run_timer()?;
                    qconn.run_events(uctx)?;
                    if qconn.next_time().is_none() {
                        qconn.run_timer()?;
                    }

                    while let Some(send_buf) = qconn.consume_data() {
                        self.socket_send(&mut client_socket, &send_buf)?;
                    }

                    if let Some(timeout) = qconn.next_time() {
                        self.next_timeout = Some(Duration::from_micros(timeout));
                    } else {
                        self.next_timeout = None;
                    }

                    if qconn.is_closed() {
                        info!("Now we exit the runtime");
                        return Ok(());
                    }
                    continue;
                }
            }

            for event in events.iter() {
                match event.token() {
                    UDP_SOCKET => {
                        loop {
                            match client_socket.recv_from(&mut udp_rcvbuf) {
                                Ok((packet_size, source_addr)) => {
                                    trace!("Received {} bytes from {}", packet_size, source_addr);
                                    self.handle_received_packet(
                                        qconn,
                                        &udp_rcvbuf[..packet_size],
                                        source_addr,
                                    )?;
                                }
                                Err(err)
                                    if err.kind() == std::io::ErrorKind::WouldBlock
                                        || err.kind() == std::io::ErrorKind::Interrupted =>
                                {
                                    break;
                                }
                                Err(err) => {
                                    // TODO: Handle QUIC connection migration (when UDP 4-tuple changes)
                                    return Err(anyhow::anyhow!("Socket read failed: {}", err)
                                        .context(format!(
                                            "Error while reading from {:?}",
                                            client_socket
                                        )));
                                }
                            }
                        }

                        qconn.run_events(uctx)?;
                        if qconn.next_time().is_none() {
                            qconn.run_timer()?;
                        }

                        while let Some(send_buf) = qconn.consume_data() {
                            self.socket_send(&mut client_socket, &send_buf)?;
                        }

                        #[cfg(target_os = "linux")]
                        {
                            if let Some(timeout) = qconn.next_time() {
                                trace!("Update timeout to {}ns", timeout);
                                if let Some(ref mut timer) = self.quic_timer {
                                    timer.set_timeout(&Duration::from_micros(timeout))?;
                                }
                            } else {
                                warn!("Should not trigger the timer process immediately!");
                            }
                        }

                        #[cfg(not(target_os = "linux"))]
                        {
                            if let Some(timeout) = qconn.next_time() {
                                self.next_timeout = Some(Duration::from_micros(timeout));
                            } else {
                                self.next_timeout = None;
                            }
                        }

                        if !self.tx_reorder_queue.is_empty() {
                            self.flush_tx_reorder_queue(&mut client_socket)?;
                        }
                        if !self.rx_reorder_queue.is_empty() {
                            self.flush_rx_reorder_queue(qconn)?;
                        }

                        if qconn.is_closed() {
                            info!("Now we exit the runtime");
                            return Ok(());
                        }
                    }
                    #[cfg(target_os = "linux")]
                    QUIC_TIMER_TOKEN => {
                        if let Some(ref mut timer) = self.quic_timer {
                            if let Ok(real_timeout) = timer.read() {
                                trace!("Timer event triggered {} times!", real_timeout);
                                qconn.run_timer()?;
                                qconn.run_events(uctx)?;
                                if qconn.next_time().is_none() {
                                    qconn.run_timer()?;
                                }

                                while let Some(send_buf) = qconn.consume_data() {
                                    self.socket_send(&mut client_socket, &send_buf)?;
                                }
                                if !self.tx_reorder_queue.is_empty() {
                                    self.flush_tx_reorder_queue(&mut client_socket)?;
                                }

                                if let Some(timeout) = qconn.next_time() {
                                    trace!("Update timeout {}ns", timeout);
                                    quic_timer.set_timeout(&Duration::from_micros(timeout))?;
                                }

                                if qconn.is_closed() {
                                    info!("Now we exit the runtime");
                                    return Ok(());
                                }
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
