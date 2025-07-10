use anyhow::{anyhow, Context, Result};
use rand::Rng;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use tracing::{error, info, trace, warn};
use types::Timespec;

use io_uring::{cqueue, opcode, types, IoUring, Probe, SubmissionQueue};
use slab::Slab;

use crate::runtime::{socket_utils, QuicCallbacks, QuicUserContext};
use crate::QuicConnection;

#[derive(Clone)]
enum Token {
    Timer {
        fd: RawFd,
    },
    TimerUpdate {
        ts: Timespec,
    },
    ReadMulti {
        fd: RawFd,
    },
    Write {
        buf_index: usize,
        datagram_len: u16,
        msghdr_ptr: *mut libc::msghdr,
        sockaddr_ptr: *mut libc::c_void,
        iovec_ptr: *mut libc::iovec,
    },
    ProvideBuffers {
        fd: RawFd,
        group_id: u16,
    },
}

impl Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Timer { fd } => write!(f, "Token::Timer fd {fd}"),
            Token::TimerUpdate { ts } => write!(f, "Token::TimerUpdate {{ ts {ts:?} }}"),
            Token::ReadMulti { fd } => write!(f, "Token::ReadMulti {{ fd: {fd} }}"),
            Token::Write {
                buf_index,
                datagram_len,
                msghdr_ptr,
                sockaddr_ptr,
                iovec_ptr,
            } => write!(
                f,
                "Token::Write {{ buf_index: {buf_index}, datagram_len: {datagram_len}, msghdr_ptr: {msghdr_ptr:?}, sockaddr_ptr: {sockaddr_ptr:?}, iovec_ptr: {iovec_ptr:?} }}",
            ),
            Token::ProvideBuffers { fd, group_id } => write!(
                f,
                "Token::ProvideBuffers {{ fd: {fd}, group_id: {group_id} }}",
            ),
        }
    }
}

#[derive(Debug)]
struct TimerContext {
    ts: *mut Timespec,
    update_ts: *mut Timespec,
    token_index: Option<usize>,
}

impl TimerContext {
    pub fn new() -> Self {
        Self {
            ts: Box::leak(Box::new(Timespec::new())) as &mut Timespec,
            update_ts: Box::leak(Box::new(Timespec::new())) as &mut Timespec,
            token_index: None,
        }
    }
}

impl Drop for TimerContext {
    fn drop(&mut self) {
        unsafe {
            std::ptr::drop_in_place(self.ts);
            std::ptr::drop_in_place(self.update_ts);
        }
    }
}

pub struct IoUringEventLoop {
    target_address: SocketAddr,
    bufpool: Vec<usize>,
    buf_alloc: Slab<Vec<u8>>,
    read_bufs: Vec<u8>,
    read_bufs_cnt: u16,
    buffer_size: usize,
    token_alloc: Slab<Token>,
    timer_context: TimerContext,
    capacity: usize,
    max_quic_packet_send_count: Option<u64>,
    sent_cnt: u64,
    tx_packet_loss_rate: Option<f32>,
    rx_packet_loss_rate: Option<f32>,
    rng: rand::rngs::ThreadRng,
    drop_packets_above_size: Option<u16>,
}

impl IoUringEventLoop {
    pub fn with_capacity(
        capacity: usize,
        buffer_size: usize,
        target_address: SocketAddr,
        max_quic_packet_send_count: Option<u64>,
        tx_packet_loss_rate: Option<f32>,
        rx_packet_loss_rate: Option<f32>,
        drop_packets_above_size: Option<u16>,
    ) -> Self {
        const MULTI_BUFFER_CNT: u16 = 20;
        Self {
            capacity,
            target_address,
            bufpool: Vec::with_capacity(capacity),
            buf_alloc: Slab::with_capacity(capacity),
            buffer_size,
            read_bufs: vec![0u8; MULTI_BUFFER_CNT as usize * buffer_size],
            read_bufs_cnt: MULTI_BUFFER_CNT,
            token_alloc: Slab::with_capacity(capacity),
            timer_context: TimerContext::new(),
            max_quic_packet_send_count,
            sent_cnt: 0,
            tx_packet_loss_rate,
            rx_packet_loss_rate,
            rng: rand::thread_rng(),
            drop_packets_above_size,
        }
    }

    fn update_and_sumbit_timer_event(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        timeout: Duration,
    ) -> Result<()> {
        let token_index = self
            .timer_context
            .token_index
            .ok_or_else(|| anyhow!("update timer, must have token index"))?;

        let ts = Timespec::new()
            .sec(timeout.as_secs())
            .nsec(timeout.subsec_nanos());
        let update_token_index = self.token_alloc.insert(Token::TimerUpdate { ts });

        unsafe {
            std::ptr::replace(self.timer_context.update_ts, ts);
        }

        let update_e = opcode::TimeoutUpdate::new(token_index as u64, self.timer_context.update_ts)
            .build()
            .user_data(update_token_index as u64);

        unsafe { sq.push(&update_e)? }
        trace!(
            "Trying to submit timer update event, timeout {:?}, token index {}, update_token_index {}",
            ts, token_index, update_token_index
        );

        sq.sync();

        Ok(())
    }

    fn create_and_sumbit_timer_event(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        timeout: Duration,
        fd: i32,
    ) -> Result<()> {
        let token_index = self.token_alloc.insert(Token::Timer { fd });
        let ts = Timespec::new()
            .sec(timeout.as_secs())
            .nsec(timeout.subsec_nanos());

        unsafe {
            std::ptr::replace(self.timer_context.ts, ts);
        }

        let timer_e = opcode::Timeout::new(self.timer_context.ts)
            .build()
            .user_data(token_index as u64);

        unsafe {
            sq.push(&timer_e)?;
        }
        trace!(
            "Trying to submit timer event, timeout {:?}, token index {}",
            timeout,
            token_index
        );

        sq.sync();

        self.timer_context.token_index = Some(token_index);

        Ok(())
    }

    fn create_and_sumbit_readmulti_event(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        fd: i32,
        group_id: u16,
    ) -> Result<()> {
        let token_index = self.token_alloc.insert(Token::ReadMulti { fd });

        let read_e = opcode::RecvMulti::new(types::Fd(fd), group_id)
            .build()
            .user_data(token_index as u64);

        unsafe { sq.push(&read_e)? }
        trace!(
            "Trying to submit read multi event, token index {}",
            token_index
        );

        sq.sync();
        Ok(())
    }

    fn create_and_sumbit_provide_buffers_event(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        group_id: u16,
        fd: i32,
    ) -> Result<()> {
        let token_index = self
            .token_alloc
            .insert(Token::ProvideBuffers { fd, group_id });

        let provide_bufs_e = opcode::ProvideBuffers::new(
            self.read_bufs.as_mut_ptr(),
            self.buffer_size as i32,
            self.read_bufs_cnt,
            group_id,
            0,
        )
        .build()
        .user_data(token_index as u64);

        trace!(
            "Trying to submit op ProvideBuffers, token index {}",
            token_index
        );
        unsafe {
            sq.push(&provide_bufs_e)?;
        }
        sq.sync();

        Ok(())
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

    fn create_and_sumbit_write_event<F>(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        fd: i32,
        mut fill_buf: F,
    ) -> Result<()>
    where
        F: FnMut(&mut [u8]) -> Result<u16>,
    {
        if self
            .max_quic_packet_send_count
            .is_some_and(|max| self.sent_cnt >= max)
        {
            info!(
                "Maximum packet send count {} reached, dropping packet",
                self.sent_cnt
            );
            return Ok(());
        }

        let buf_index = match self.bufpool.pop() {
            Some(index) => index,
            None => {
                let buf = vec![0u8; self.buffer_size];
                let buf_entry = self.buf_alloc.vacant_entry();
                let index = buf_entry.key();
                buf_entry.insert(buf);
                index
            }
        };

        let datagram_len = {
            let buf = &mut self.buf_alloc[buf_index];
            fill_buf(buf)?
        };

        if self.should_drop_tx_packet(datagram_len as usize) {
            trace!(
                "Simulating TX packet loss - dropping {} bytes",
                datagram_len
            );
            self.bufpool.push(buf_index);
            return Ok(());
        }

        // For io_uring migration support, use SendMsg to implement sendto functionality
        let (write_e, msghdr_ptr, sockaddr_ptr, iovec_ptr) = {
            let buf = &self.buf_alloc[buf_index];

            // Create iovec for the buffer and store on heap
            let iovec = libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: datagram_len as libc::size_t,
            };
            let iovec_box = Box::new(iovec);
            let iovec_ptr = Box::into_raw(iovec_box);

            // Create sockaddr for target address
            let (sockaddr_ptr, sockaddr_len) = match self.target_address {
                std::net::SocketAddr::V4(addr_v4) => {
                    let sockaddr = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: addr_v4.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(addr_v4.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    };
                    // Store sockaddr on heap and get pointer
                    let sockaddr_box = Box::new(sockaddr);
                    let sockaddr_ptr = Box::into_raw(sockaddr_box);
                    (
                        sockaddr_ptr as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as u32,
                    )
                }
                std::net::SocketAddr::V6(addr_v6) => {
                    let sockaddr = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: addr_v6.port().to_be(),
                        sin6_flowinfo: addr_v6.flowinfo(),
                        sin6_addr: libc::in6_addr {
                            s6_addr: addr_v6.ip().octets(),
                        },
                        sin6_scope_id: addr_v6.scope_id(),
                    };
                    // Store sockaddr on heap and get pointer
                    let sockaddr_box = Box::new(sockaddr);
                    let sockaddr_ptr = Box::into_raw(sockaddr_box);
                    (
                        sockaddr_ptr as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in6>() as u32,
                    )
                }
            };

            // Create msghdr structure
            let msghdr = libc::msghdr {
                msg_name: sockaddr_ptr as *mut libc::c_void,
                msg_namelen: sockaddr_len,
                msg_iov: iovec_ptr,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };

            // Store msghdr on heap to keep it alive during the async operation
            let msghdr_box = Box::new(msghdr);
            let msghdr_ptr = Box::into_raw(msghdr_box);

            let write_e = opcode::SendMsg::new(types::Fd(fd), msghdr_ptr)
                .build()
                .user_data(0); // Will be set after token creation

            (
                write_e,
                msghdr_ptr,
                sockaddr_ptr as *mut libc::c_void,
                iovec_ptr,
            )
        };

        let token_index = self.token_alloc.insert(Token::Write {
            buf_index,
            datagram_len,
            msghdr_ptr,
            sockaddr_ptr,
            iovec_ptr,
        });

        // Update the user_data with the actual token index
        let write_e = write_e.user_data(token_index as u64);

        unsafe { sq.push(&write_e)? }
        trace!(
            "Trying to submit write event, token index {}, datagram len {}, target: {}",
            token_index,
            datagram_len,
            self.target_address
        );

        sq.sync();
        self.sent_cnt += 1;
        Ok(())
    }

    fn add_timer(&mut self, sq: &mut SubmissionQueue<'_>, udp_fd: i32, timeout: u64) -> Result<()> {
        trace!("updating idle timeout to {}ns", timeout);
        if self.timer_context.token_index.is_some() {
            self.update_and_sumbit_timer_event(sq, Duration::from_micros(timeout))?;
        } else {
            self.create_and_sumbit_timer_event(sq, Duration::from_micros(timeout), udp_fd)?;
        }
        Ok(())
    }

    fn handle_send_error(&mut self, ret: i32, datagram_len: u16) -> Result<()> {
        if ret >= 0 {
            return Ok(());
        }
        let io_error = std::io::Error::from_raw_os_error(-ret);
        socket_utils::handle_socket_send_error(
            &io_error,
            &self.target_address,
            Some(datagram_len as usize),
        )
    }

    fn handle_receive_error(&mut self, ret: i32) -> Result<()> {
        if ret >= 0 {
            return Ok(());
        }
        let io_error = std::io::Error::from_raw_os_error(-ret);
        socket_utils::handle_socket_recv_error(&io_error)
    }

    pub fn run<T>(
        &mut self,
        qconn: &mut QuicConnection,
        uctx: &mut QuicUserContext<T>,
    ) -> Result<()>
    where
        T: QuicCallbacks,
    {
        let mut uring = IoUring::new(self.capacity as u32)?;
        let (submitter, mut sq, mut cq) = uring.split();
        let mut probe = Probe::new();
        submitter.register_probe(&mut probe)?;
        info!(
            "IoUring timer operation supported: {}",
            probe.is_supported(opcode::Timeout::CODE)
        );
        info!(
            "IoUring timer update operation supported: {}",
            probe.is_supported(opcode::TimeoutUpdate::CODE)
        );
        info!(
            "IoUring read multi operation supported: {}",
            probe.is_supported(opcode::RecvMulti::CODE)
        );
        info!(
            "IoUring sendmsg operation supported: {}",
            probe.is_supported(opcode::SendMsg::CODE)
        );

        if !probe.is_supported(opcode::Timeout::CODE) {
            return Err(anyhow!("IoUring timer operation not supported"));
        }
        if !probe.is_supported(opcode::TimeoutUpdate::CODE) {
            return Err(anyhow!("IoUring timer update operation not supported"));
        }
        if !probe.is_supported(opcode::RecvMulti::CODE) {
            return Err(anyhow!("IoUring read multi operation not supported"));
        }
        if !probe.is_supported(opcode::SendMsg::CODE) {
            return Err(anyhow!("IoUring sendmsg operation not supported"));
        }

        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .with_context(|| "Failed to bind UDP socket to random address")?;

        let max_udp_payload_size =
            super::socket_utils::get_max_udp_payload_size_from_device_mtu(&udp_socket);

        // Set socket to non-blocking mode
        udp_socket
            .set_nonblocking(true)
            .with_context(|| "Failed to set UDP socket to non-blocking mode")?;

        // Set DF (Don't Fragment) flag on the socket
        super::socket_utils::set_dont_fragment(&udp_socket);

        let udp_fd = udp_socket.as_raw_fd();
        let local_addr = udp_socket.local_addr().with_context(|| {
            format!("Failed to get local address from native socket {udp_socket:?}",)
        })?;
        let _span = tracing::span!(
            tracing::Level::TRACE,
            "udp",
            local=?format!("{}:{}", local_addr.ip(), local_addr.port()),
            peer=?format!("{}:{}", self.target_address.ip(), self.target_address.port())
        )
        .entered();

        trace!(
            "Created UDP socket with local address: {}, file descriptor: {}",
            local_addr,
            udp_fd
        );

        self.create_and_sumbit_write_event(&mut sq, udp_fd, |buf| {
            qconn.connect(max_udp_payload_size)?;
            let (udp_sndbuf, target_addr) = qconn
                .consume_data()
                .expect("Should have first initial QUIC packet");

            // Should not change the buf size, just use this buf
            let snd_len = udp_sndbuf.len();
            trace!(
                "First write event, buf size {}, datagram len {}, target: {}",
                buf.len(),
                snd_len,
                target_addr
            );
            buf[..snd_len].copy_from_slice(&udp_sndbuf[..]);
            Ok(snd_len as u16)
        })?;

        const BUF_GROUP_ID: u16 = 0xdead;

        self.create_and_sumbit_provide_buffers_event(&mut sq, BUF_GROUP_ID, udp_fd)?;
        if let Some(timeout) = qconn.next_time() {
            trace!("Update timeout to {}ns", timeout);
            self.add_timer(&mut sq, udp_fd, timeout)?;
        } else {
            warn!("Should not trigger the timer process immediately!");
        }

        loop {
            trace!("IoUring submit!");
            match submitter.submit_and_wait(1) {
                Ok(_) => (),
                Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => {
                    warn!("IoUring EBUSY - ring is busy, will retry");
                    continue;
                }
                Err(ref err) if err.raw_os_error() == Some(libc::EINTR) => {
                    trace!("IoUring interrupted by signal, will retry");
                    continue;
                }
                Err(err) => {
                    error!("IoUring submit_and_wait failed: {}", err);
                    return Err(err.into());
                }
            }

            cq.sync();

            let mut recv_evt_triggered = false;
            qconn.update_current_time();
            for cqe in &mut cq {
                let ret = cqe.result();
                let flags = cqe.flags();
                let token_index = cqe.user_data() as usize;

                trace!(
                    "Completion queue event - token_index: {}, result: {}, flags: {}, tokens: {:?}",
                    token_index,
                    ret,
                    flags,
                    &self.token_alloc
                );

                let token = self.token_alloc[token_index].clone();
                match token {
                    Token::TimerUpdate { ts } => {
                        trace!("Updating timer to {:?}, result: {ret}", ts);
                        self.token_alloc.remove(token_index);
                    }
                    Token::Timer { .. } => {
                        let timer_token_index = self
                            .timer_context
                            .token_index
                            .ok_or_else(|| anyhow!("update timer, must have token index"))?;
                        assert_eq!(token_index, timer_token_index);
                        trace!("Timer expired after {:?}", token);
                        self.token_alloc.remove(token_index);
                        self.timer_context.token_index = None;

                        qconn.run_timer()?;
                        qconn.run_events(uctx)?;
                        if qconn.next_time().is_none() {
                            qconn.run_timer()?;
                        }
                        if let Some(timeout) = qconn.next_time() {
                            self.add_timer(&mut sq, udp_fd, timeout)?;
                        } else {
                            warn!("Should not trigger the timer process immediately!");
                        }

                        let buffer_size = self.buffer_size;
                        while let Some((send_buf, target_addr)) = qconn.consume_data() {
                            // Update target address if it has changed (migration happens automatically)
                            if target_addr != self.target_address {
                                info!(
                                    "Connection migration detected: {} -> {}",
                                    self.target_address, target_addr
                                );
                                self.target_address = target_addr;
                            }

                            trace!(
                                "Sending {} bytes to {}, triggered by timer",
                                send_buf.len(),
                                self.target_address
                            );
                            self.create_and_sumbit_write_event(&mut sq, udp_fd, |buf| {
                                let snd_len = send_buf.len();
                                if buf.len() < snd_len {
                                    warn!(
                                        "Send buffer size {} insufficient for send buffer {}",
                                        buffer_size, snd_len
                                    );
                                    return Ok(0);
                                }
                                buf[..snd_len].copy_from_slice(&send_buf[..]);
                                Ok(snd_len as u16)
                            })?;
                        }
                        if let Some(timeout) = qconn.next_time() {
                            self.add_timer(&mut sq, udp_fd, timeout)?;
                        } else {
                            warn!("Should not trigger the timer process immediately!");
                        }

                        if qconn.is_closed() {
                            info!("Now we exit the runtime");
                            return Ok(());
                        }
                    }
                    Token::ProvideBuffers { group_id, fd } => {
                        trace!("Initializing buffer group");
                        self.create_and_sumbit_readmulti_event(&mut sq, fd, group_id)?;
                        self.token_alloc.remove(token_index);
                    }
                    Token::Write {
                        buf_index,
                        datagram_len,
                        msghdr_ptr,
                        sockaddr_ptr,
                        iovec_ptr,
                    } => {
                        // Handle send errors with comprehensive error classification
                        if let Err(err) = self.handle_send_error(ret, datagram_len) {
                            error!("Failed to handle send error: {}", err);
                            // Continue processing but log the error
                        }

                        if ret >= 0 {
                            let write_len = ret as u16;
                            trace!(
                                "Write operation completed - {} bytes written, {:?}",
                                write_len,
                                token,
                            );
                            if write_len != datagram_len {
                                warn!(
                                    "Write error - incorrect write length {} (expected {}), {:?}",
                                    write_len, datagram_len, token
                                );
                            }
                        } else {
                            warn!(
                                "Write operation failed with error code {}, {:?}",
                                ret, token
                            );
                        }

                        // Clean up: restore the buffer, free allocated memory, and remove the token
                        unsafe {
                            if !msghdr_ptr.is_null() {
                                let _ = Box::from_raw(msghdr_ptr);
                            }
                            if !sockaddr_ptr.is_null() {
                                let _ = Box::from_raw(sockaddr_ptr as *mut libc::sockaddr);
                            }
                            if !iovec_ptr.is_null() {
                                let _ = Box::from_raw(iovec_ptr);
                            }
                        }
                        self.token_alloc.remove(token_index);
                        self.bufpool.push(buf_index);
                    }
                    Token::ReadMulti { fd } => {
                        let more = cqueue::more(flags);
                        if !more {
                            self.create_and_sumbit_provide_buffers_event(
                                &mut sq,
                                BUF_GROUP_ID,
                                fd,
                            )?;
                            self.token_alloc.remove(token_index);
                            continue;
                        }

                        // Handle receive errors with comprehensive error classification
                        if let Err(err) = self.handle_receive_error(ret) {
                            error!("Failed to handle receive error: {}", err);
                            self.token_alloc.remove(token_index);
                            continue;
                        }

                        if ret < 0 {
                            // Error already handled by handle_receive_error, just continue
                            self.token_alloc.remove(token_index);
                            continue;
                        }

                        let cur_buf_index = cqueue::buffer_select(flags)
                            .ok_or_else(|| anyhow!("Should get buf index, flag {}", flags))?;

                        let read_len = ret as usize;
                        trace!(
                            "ReadMulti event received - {} bytes read, buffer index: {}, more data: {}",
                            read_len,
                            cur_buf_index,
                            more
                        );

                        if self.should_drop_rx_packet(read_len) {
                            trace!("Simulating RX packet loss - dropping {} bytes", read_len);
                            continue;
                        }

                        let buffer_size = self.buffer_size;
                        let buf_start = buffer_size * cur_buf_index as usize;
                        let read_buf = &mut self.read_bufs[buf_start..buf_start + read_len];

                        qconn.provide_data(read_buf, self.target_address)?;
                        recv_evt_triggered = true;
                    }
                }
            }

            if !recv_evt_triggered {
                continue;
            }

            qconn.run_events(uctx)?;
            if qconn.next_time().is_none() {
                qconn.run_timer()?;
            }

            // Migration is now handled automatically in consume_data()

            let buffer_size = self.buffer_size;
            while let Some((send_buf, target_addr)) = qconn.consume_data() {
                // Update target address if it has changed (migration happens automatically)
                if target_addr != self.target_address {
                    info!(
                        "Connection migration detected: {} -> {}",
                        self.target_address, target_addr
                    );
                    self.target_address = target_addr;
                }

                trace!(
                    "sending {} bytes to {}",
                    send_buf.len(),
                    self.target_address
                );

                self.create_and_sumbit_write_event(&mut sq, udp_fd, |buf| {
                    let snd_len = send_buf.len();
                    if buf.len() < snd_len {
                        warn!(
                            "send buffer size {} insufficient for send buffer {}",
                            buffer_size, snd_len
                        );
                        return Ok(0);
                    }
                    buf[..snd_len].copy_from_slice(&send_buf[..]);
                    Ok(snd_len as u16)
                })?;
            }

            if let Some(timeout) = qconn.next_time() {
                self.add_timer(&mut sq, udp_fd, timeout)?;
            } else {
                warn!("Should not trigger the timer process immediately!");
            }

            if qconn.is_closed() {
                info!("Now we exit the runtime");
                return Ok(());
            }
        }
    }
}
