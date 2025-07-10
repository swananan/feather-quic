use crate::runtime::{socket_utils, QuicUserContext};
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
use tracing::{error, info, trace, warn};

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

    drop_packets_above_size: Option<u16>,
}

impl MioEventLoop {
    const UDP_SOCKET: Token = Token(0);
    #[cfg(target_os = "linux")]
    const QUIC_TIMER_TOKEN: Token = Token(1);

    pub fn new(
        target_address: SocketAddr,
        max_quic_packet_send_count: Option<u64>,
        tx_packet_loss_rate: Option<f32>,
        rx_packet_loss_rate: Option<f32>,
        tx_packet_reorder_rate: Option<f32>,
        rx_packet_reorder_rate: Option<f32>,
        drop_packets_above_size: Option<u16>,
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

            drop_packets_above_size,
        }
    }

    fn should_drop_tx_packet(&mut self, packet_size: usize) -> bool {
        if let Some(max_size) = self.drop_packets_above_size {
            if packet_size > max_size as usize {
                trace!(
                    "Dropping TX packet of size {} (above limit of {})",
                    packet_size,
                    max_size
                );
                return true;
            }
        }
        if let Some(packet_loss_rate) = self.tx_packet_loss_rate {
            self.rng.gen::<f32>() < packet_loss_rate
        } else {
            false
        }
    }

    fn should_drop_rx_packet(&mut self, packet_size: usize) -> bool {
        if let Some(max_size) = self.drop_packets_above_size {
            if packet_size > max_size as usize {
                trace!(
                    "Dropping RX packet of size {} (above limit of {})",
                    packet_size,
                    max_size
                );
                return true;
            }
        }
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

    fn create_client_socket(&self) -> Result<(UdpSocket, Option<u16>)> {
        let std_socket = std::net::UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>()?)
            .with_context(|| "Failed to bind random address".to_string())?;

        let max_udp_payload_size =
            super::socket_utils::get_max_udp_payload_size_from_device_mtu(&std_socket);

        // Set socket to non-blocking mode
        std_socket.set_nonblocking(true)?;

        // Set DF (Don't Fragment) flag on the socket
        super::socket_utils::set_dont_fragment(&std_socket);

        // Convert to Mio socket after setting socket options
        let client_socket = UdpSocket::from_std(std_socket);

        Ok((client_socket, max_udp_payload_size))
    }

    fn socket_recv_with_error_handling(
        &mut self,
        client_socket: &mut UdpSocket,
        buffer: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr)>> {
        match client_socket.recv_from(buffer) {
            Ok((packet_size, remote_addr)) => {
                trace!("Received {} bytes from {}", packet_size, remote_addr);
                Ok(Some((packet_size, remote_addr)))
            }
            Err(err) => match socket_utils::handle_socket_recv_error(&err) {
                Ok(()) => Ok(None),
                Err(e) => Err(e),
            },
        }
    }

    fn socket_send_with_error_handling(
        &mut self,
        client_socket: &mut UdpSocket,
        snd_buf: &[u8],
    ) -> Result<()> {
        match self.socket_send(client_socket, snd_buf) {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(io_error) = e.downcast_ref::<std::io::Error>() {
                    socket_utils::handle_socket_send_error(
                        io_error,
                        &self.target_address,
                        Some(snd_buf.len()),
                    )?;
                }
                Err(e)
            }
        }
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

        if self.should_drop_tx_packet(snd_buf.len()) {
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
                    client_socket.send_to(&delayed_packet, self.target_address)?;
                    trace!(
                        "Sending reordered TX packet - {} bytes to {}",
                        delayed_packet.len(),
                        self.target_address
                    );
                }
            }
        } else {
            client_socket.send_to(snd_buf, self.target_address)?;
            trace!("Sending {} bytes to {}", snd_buf.len(), self.target_address);
        }

        self.sent_cnt += 1;
        Ok(())
    }

    fn handle_received_packet(
        &mut self,
        qconn: &mut QuicConnection,
        packet_data: &[u8],
        remote_addr: SocketAddr,
    ) -> Result<()> {
        if self.should_drop_rx_packet(packet_data.len()) {
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
                .push_back((packet_data.to_vec(), remote_addr));

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
            qconn.provide_data(packet_data, remote_addr)?;
            trace!(
                "Processing {} bytes from {}",
                packet_data.len(),
                remote_addr
            );
        }

        Ok(())
    }

    fn flush_tx_reorder_queue(&mut self, client_socket: &mut UdpSocket) -> Result<()> {
        while let Some(packet) = self.tx_reorder_queue.pop_front() {
            self.socket_send_with_error_handling(client_socket, &packet)?;
            trace!("Flushing reordered TX packet - {} bytes", packet.len());
        }
        Ok(())
    }

    fn flush_rx_reorder_queue(&mut self, qconn: &mut QuicConnection) -> Result<()> {
        while let Some((packet_data, remote_addr)) = self.rx_reorder_queue.pop_front() {
            self.handle_received_packet(qconn, &packet_data, remote_addr)?;
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

        let (mut client_socket, max_udp_payload_size) = self.create_client_socket()?;

        let local_addr = client_socket.local_addr().with_context(|| {
            format!("Failed to get local address from Mio socket {client_socket:?}",)
        })?;
        let _span = tracing::span!(
            tracing::Level::TRACE,
            "udp",
            local=?format!("{}:{}", local_addr.ip(), local_addr.port()),
            peer=?format!("{}:{}", self.target_address.ip(), self.target_address.port())
        )
        .entered();

        poll.registry()
            .register(&mut client_socket, Self::UDP_SOCKET, Interest::READABLE)?;

        #[cfg(target_os = "linux")]
        {
            if let Some(ref mut timer) = self.quic_timer {
                poll.registry()
                    .register(timer, Self::QUIC_TIMER_TOKEN, Interest::READABLE)?;
            }
        }

        qconn.connect(max_udp_payload_size)?;
        let (udp_sndbuf, target_addr) = qconn
            .consume_data()
            .expect("Should have first initial QUIC packet");

        // Update target address from QUIC path management
        self.target_address = target_addr;

        self.socket_send_with_error_handling(&mut client_socket, &udp_sndbuf)?;
        info!(
            "Initiating QUIC handshake, first UDP Datagram size {}, target: {}",
            udp_sndbuf.len(),
            target_addr
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

                    while let Some((send_buf, target_addr)) = qconn.consume_data() {
                        // Update target address if it has changed
                        self.target_address = target_addr;
                        self.socket_send_with_error_handling(&mut client_socket, &send_buf)?;
                    }

                    if let Some(timeout) = qconn.next_time() {
                        self.next_timeout = if timeout != u64::MAX {
                            Some(Duration::from_micros(timeout))
                        } else {
                            None
                        }
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
                    Self::UDP_SOCKET => {
                        loop {
                            // TODO: Consider processing ICMP packets to optimize MTU discovery:
                            // 1. ICMP "Packet Too Big" messages can provide immediate feedback about path MTU
                            // 2. This could accelerate MTU discovery by avoiding unnecessary probe attempts
                            // 3. May improve connection performance by finding optimal MTU faster
                            match self.socket_recv_with_error_handling(
                                &mut client_socket,
                                &mut udp_rcvbuf,
                            ) {
                                Ok(Some((packet_size, remote_addr))) => {
                                    self.handle_received_packet(
                                        qconn,
                                        &udp_rcvbuf[..packet_size],
                                        remote_addr,
                                    )?;
                                }
                                Ok(None) => {
                                    // No data available or recoverable error occurred
                                    break;
                                }
                                Err(err) => {
                                    // Critical error that requires terminating the connection
                                    error!("Critical UDP receive error: {}", err);
                                    return Err(err);
                                }
                            }
                        }

                        qconn.run_events(uctx)?;
                        if qconn.next_time().is_none() {
                            qconn.run_timer()?;
                        }

                        while let Some((send_buf, target_addr)) = qconn.consume_data() {
                            // Update target address if it has changed (migration happens automatically)
                            if target_addr != self.target_address {
                                info!(
                                    "Connection migration detected: {} -> {}",
                                    self.target_address, target_addr
                                );
                                self.target_address = target_addr;
                            }

                            self.socket_send_with_error_handling(&mut client_socket, &send_buf)?;
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
                    Self::QUIC_TIMER_TOKEN => {
                        if let Some(ref mut timer) = self.quic_timer {
                            if let Ok(real_timeout) = timer.read() {
                                trace!("Timer event triggered {} times!", real_timeout);
                                qconn.run_timer()?;
                                qconn.run_events(uctx)?;
                                if qconn.next_time().is_none() {
                                    qconn.run_timer()?;
                                }

                                while let Some((send_buf, target_addr)) = qconn.consume_data() {
                                    // Update target address if it has changed
                                    self.target_address = target_addr;
                                    self.socket_send_with_error_handling(
                                        &mut client_socket,
                                        &send_buf,
                                    )?;
                                }
                                if !self.tx_reorder_queue.is_empty() {
                                    self.flush_tx_reorder_queue(&mut client_socket)?;
                                }

                                if let Some(timeout) = qconn.next_time() {
                                    trace!("Update timeout {}ns", timeout);
                                    if let Some(ref mut timer) = self.quic_timer {
                                        timer.set_timeout(&Duration::from_micros(timeout))?;
                                    }
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
