use anyhow::{anyhow, Result};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use tracing::{info, trace, warn};
use types::Timespec;

use io_uring::{cqueue, opcode, types, IoUring, Probe, SubmissionQueue};
use slab::Slab;

use crate::runtime::{QuicCallbacks, QuicUserContext};
use crate::QuicConnection;

#[derive(Clone)]
enum Token {
    Timer,
    TimerUpdate { ts: Timespec },
    ReadMulti { fd: RawFd },
    Write { buf_index: usize, datagram_len: u16 },
    ProvideBuffers { fd: RawFd, group_id: u16 },
}

impl Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Timer => write!(f, "Token::Timer "),
            Token::TimerUpdate { ts } => write!(f, "Token::TimerUpdate {{ ts {:?} }}", ts),
            Token::ReadMulti { fd } => write!(f, "Token::ReadMulti {{ fd: {} }}", fd),
            Token::Write {
                buf_index,
                datagram_len,
            } => write!(
                f,
                "Token::Write {{ buf_index: {}, datagram_len: {} }}",
                buf_index, datagram_len
            ),
            Token::ProvideBuffers { fd, group_id } => write!(
                f,
                "Token::ProvideBuffers {{ fd: {}, group_id: {} }}",
                fd, group_id
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
}

impl IoUringEventLoop {
    pub fn with_capacity(capacity: usize, buffer_size: usize, target_address: SocketAddr) -> Self {
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
            "Trying to sumbit timer update event, timeout {:?}, token index {}, update_token_index {}",
            ts, token_index, update_token_index
        );

        sq.sync();

        Ok(())
    }

    fn create_and_sumbit_timer_event(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        timeout: Duration,
    ) -> Result<()> {
        let token_index = self.token_alloc.insert(Token::Timer);
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
            "Trying to sumbit timer event, timeout {:?}, token index {}",
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
            "Trying to sumbit read multi event, token index {}",
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
            "Trying to sumbit op ProvideBuffers, token index {}",
            token_index
        );
        unsafe {
            sq.push(&provide_bufs_e)?;
        }
        sq.sync();

        Ok(())
    }

    fn create_and_sumbit_write_event<F>(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        fd: i32,
        prepare_data: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<u16>,
    {
        let (buf_index, buf) = match self.bufpool.pop() {
            Some(buf_index) => (buf_index, &mut self.buf_alloc[buf_index]),
            None => {
                let buf = vec![0u8; self.buffer_size];
                let buf_entry = self.buf_alloc.vacant_entry();
                let buf_index = buf_entry.key();
                buf_entry.insert(buf);

                (buf_index, &mut self.buf_alloc[buf_index])
            }
        };

        let write_len = prepare_data(buf)?;

        let token_index = self.token_alloc.insert(Token::Write {
            buf_index,
            datagram_len: write_len,
        });

        let send_e = opcode::Send::new(types::Fd(fd), buf.as_ptr(), write_len as u32)
            .build()
            .user_data(token_index as u64);

        trace!(
            "Attempting to submit write operation, length: {}, token index: {}",
            write_len,
            token_index,
        );

        // I guess sq push will not hold ref send_e, so it's totally fine
        unsafe { sq.push(&send_e)? }

        sq.sync();
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
            "IoUring send operation supported: {}",
            probe.is_supported(opcode::Send::CODE)
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
        if !probe.is_supported(opcode::Send::CODE) {
            return Err(anyhow!("IoUring send operation not supported"));
        }

        let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
        udp_socket.connect(self.target_address)?;
        let udp_fd = udp_socket.as_raw_fd();
        trace!(
            "Created UDP socket with local address: {}, file descriptor: {}",
            udp_socket.local_addr()?,
            udp_fd
        );

        self.create_and_sumbit_write_event(&mut sq, udp_fd, |buf| {
            qconn.connect()?;
            let udp_sndbuf = qconn
                .consume_data()
                .expect("Should have first initial QUIC packet");

            buf.clear();
            buf.extend(udp_sndbuf);
            Ok(buf.len() as u16)
        })?;

        const BUF_GROUP_ID: u16 = 0xdead;

        self.create_and_sumbit_provide_buffers_event(&mut sq, BUF_GROUP_ID, udp_fd)?;
        self.create_and_sumbit_timer_event(
            &mut sq,
            Duration::from_millis(qconn.get_idle_timeout()),
        )?;

        let mut connect_done_trigger = false;
        loop {
            trace!("IoUring sumbit!");
            match submitter.submit_and_wait(1) {
                Ok(_) => (),
                Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => warn!("IoUring EBUSY"),
                Err(err) => return Err(err.into()),
            }

            cq.sync();

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

                let token = &mut self.token_alloc[token_index];
                match token.clone() {
                    Token::TimerUpdate { ts } => {
                        trace!("Updating timer to {:?}, result: {ret}", ts);
                        self.token_alloc.remove(token_index);
                    }
                    Token::Timer => {
                        let timer_token_index = self
                            .timer_context
                            .token_index
                            .ok_or_else(|| anyhow!("update timer, must have token index"))?;
                        assert_eq!(token_index, timer_token_index);
                        trace!("Timer expired after {:?}", token);
                        self.token_alloc.remove(token_index);
                        self.timer_context.token_index = None;
                    }
                    Token::ProvideBuffers { group_id, fd } => {
                        trace!("Initializing buffer group");
                        self.create_and_sumbit_readmulti_event(&mut sq, fd, group_id)?;
                        self.token_alloc.remove(token_index);
                    }
                    Token::Write {
                        buf_index,
                        datagram_len,
                    } => {
                        let write_len = ret as u16;

                        trace!(
                            "Write operation completed - {} bytes written, {:?}",
                            write_len,
                            token,
                        );
                        if write_len != datagram_len {
                            trace!(
                                "Write error - incorrect write length {}, {:?}",
                                write_len,
                                token
                            );
                        }

                        // Clean up: restore the buffer and remove the token
                        self.token_alloc.remove(token_index);
                        self.bufpool.push(buf_index);
                    }
                    Token::ReadMulti { fd } => {
                        let cur_buf_index = cqueue::buffer_select(flags)
                            .ok_or_else(|| anyhow!("Should get buf index, flag {}", flags))?;

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

                        if ret < 0 {
                            warn!(
                                "{:?} index {}, error occurred: {:?}",
                                token,
                                token_index,
                                std::io::Error::from_raw_os_error(-ret)
                            );
                            self.token_alloc.remove(token_index);
                            continue;
                        }

                        let read_len = ret as usize;
                        trace!(
                            "ReadMulti event received - {} bytes read, buffer index: {}, more data: {}",
                            read_len,
                            cur_buf_index,
                            more
                        );

                        if self.timer_context.token_index.is_some() {
                            self.update_and_sumbit_timer_event(
                                &mut sq,
                                Duration::from_millis(5000),
                            )?;
                        } else {
                            self.create_and_sumbit_timer_event(
                                &mut sq,
                                Duration::from_millis(5000),
                            )?;
                        }

                        let buffer_size = self.buffer_size;
                        let buf_start = buffer_size * cur_buf_index as usize;
                        let read_buf = &mut self.read_bufs[buf_start..buf_start + read_len];

                        qconn.update_current_time();

                        qconn.provide_data(read_buf, self.target_address)?;

                        while let Some(send_buf) = qconn.consume_data() {
                            trace!(
                                "Sending {} bytes to {}",
                                send_buf.len(),
                                self.target_address
                            );
                            self.create_and_sumbit_write_event(&mut sq, fd, |buf| {
                                let snd_len = send_buf.len();
                                if buf.len() < snd_len {
                                    warn!(
                                        "Send buffer size {} insufficient for send buffer {}",
                                        buffer_size, snd_len
                                    );
                                    return Ok(0);
                                }
                                buf[..snd_len].copy_from_slice(&send_buf[..snd_len]);
                                Ok(snd_len as u16)
                            })?;
                        }

                        // Update the idle timer
                        if let Some(timeout) = qconn.next_time() {
                            trace!("Updating idle timeout to {}ms", timeout);
                            if self.timer_context.token_index.is_some() {
                                self.update_and_sumbit_timer_event(
                                    &mut sq,
                                    Duration::from_millis(timeout),
                                )?;
                            } else {
                                self.create_and_sumbit_timer_event(
                                    &mut sq,
                                    Duration::from_millis(timeout),
                                )?;
                            }
                        }

                        // TODO: When QUIC handshake is completed, client can send some data.
                        // like HTTP/3 traffic actually
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
                }
            }
        }
    }
}
