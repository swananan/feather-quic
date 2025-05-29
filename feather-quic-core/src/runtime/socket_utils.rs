use std::net::UdpSocket;
use tracing::warn;

/// Sets the Don't Fragment (DF) flag on a UDP socket.
/// This is important for QUIC as it handles packet fragmentation itself.
pub(crate) fn set_dont_fragment(socket: &UdpSocket) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = 1;
        unsafe {
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            ) < 0
            {
                warn!("Failed to set IP_MTU_DISCOVER on socket");
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = 1;
        unsafe {
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_DONTFRAG,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            ) < 0
            {
                warn!("Failed to set IP_DONTFRAG on socket");
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IP_DONTFRAGMENT, SOCKET,
        };
        let socket = socket.as_raw_socket() as SOCKET;
        let val: i32 = 1;
        unsafe {
            if setsockopt(
                socket,
                IPPROTO_IP as i32,
                IP_DONTFRAGMENT as i32,
                &val as *const _ as *const i8,
                std::mem::size_of_val(&val) as i32,
            ) != 0
            {
                warn!("Failed to set IP_DONTFRAGMENT on socket");
            }
        }
    }
}
