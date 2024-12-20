use crate::runtime::io_uring::IoUringEventLoop;
use crate::runtime::mio::MioEventLoop;
use crate::QuicConnection;

use anyhow::Result;
use std::net::SocketAddr;

mod io_uring;
mod mio;

pub struct QuicUserContext<T> {
    user_data: T,
}

impl<T> QuicUserContext<T> {
    pub fn new(user_data: T) -> Self {
        Self { user_data }
    }
}

pub trait QuicCallbacks {
    fn connect_done(&mut self, qconn: &mut QuicConnection) -> Result<()>;
    fn read_event(&mut self, qconn: &mut QuicConnection) -> Result<()>;
    fn write_event(&mut self, qconn: &mut QuicConnection) -> Result<()>;
    fn close(&mut self, qconn: &mut QuicConnection) -> Result<()>;
}

pub enum QuicRuntimeCore {
    Mio(MioEventLoop),
    IoUring(IoUringEventLoop),
}

pub struct QuicRuntime {
    core: QuicRuntimeCore,
}

impl QuicRuntime {
    pub fn new(use_io_uring: bool, target_address: SocketAddr) -> Self {
        let core = if !use_io_uring {
            QuicRuntimeCore::Mio(MioEventLoop::new(target_address))
        } else {
            const IOURING_CAPACITY: usize = 256;
            const BUFFER_SIZE: usize = 4096;
            QuicRuntimeCore::IoUring(IoUringEventLoop::with_capacity(
                IOURING_CAPACITY,
                BUFFER_SIZE,
                target_address,
            ))
        };

        Self { core }
    }

    pub fn run<T>(
        &mut self,
        qconn: &mut QuicConnection,
        uctx: &mut QuicUserContext<T>,
    ) -> Result<()>
    where
        T: QuicCallbacks,
    {
        match self.core {
            QuicRuntimeCore::Mio(ref mut event_loop) => event_loop.run(qconn, uctx)?,
            QuicRuntimeCore::IoUring(ref mut event_loop) => event_loop.run(qconn, uctx)?,
        }

        Ok(())
    }
}
