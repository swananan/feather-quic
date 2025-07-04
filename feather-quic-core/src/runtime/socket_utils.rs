#[cfg(target_os = "linux")]
use libc::{self, c_int, getsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_MTU, IP_MTU};
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use crate::transport_parameters::{MAX_UDP_PAYLOAD_SIZE, MIN_UDP_PAYLOAD_SIZE};

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

#[cfg(target_os = "linux")]
/// Calculates the maximum UDP payload size based on the current device's MTU.
/// The socket must be connected to the target address before calling this function.
/// Returns None if the operation fails or the socket is not connected.
///
/// Note: This function returns the MTU of the local network interface. If the connection
/// goes through a tunnel (like WireGuard) or has a different path MTU, the actual
/// maximum payload size might be smaller. However, this is not a problem because:
/// 1. QUIC has built-in MTU discovery mechanism that will automatically adjust
///    the packet size if needed
/// 2. The path MTU discovery will ensure we don't exceed the actual path MTU
///
/// This function is only available on Linux platforms.
pub(crate) fn get_max_udp_payload_size_from_device_mtu(socket: &UdpSocket) -> Option<u16> {
    unsafe {
        let sock = socket.as_raw_fd();
        let (proto, opt) = if socket.local_addr().unwrap().is_ipv4() {
            (IPPROTO_IP, IP_MTU)
        } else {
            (IPPROTO_IPV6, IPV6_MTU)
        };

        let mut mtu: c_int = 0;
        let mut len = std::mem::size_of::<c_int>() as u32;

        if getsockopt(sock, proto, opt, &mut mtu as *mut _ as *mut _, &mut len) == 0 {
            // IPv4: MTU - 20(IP header) - 8(UDP header)
            // IPv6: MTU - 40(IP header) - 8(UDP header)
            let max_payload = if socket.local_addr().unwrap().is_ipv4() {
                (mtu - 28) as u16
            } else {
                (mtu - 48) as u16
            };
            info!(
                "Get [MTU] max UDP payload size: {} from device",
                max_payload
            );
            Some(max_payload.clamp(MIN_UDP_PAYLOAD_SIZE, MAX_UDP_PAYLOAD_SIZE))
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
/// TODO: Implement this function for other platforms.
pub(crate) fn get_max_udp_payload_size_from_device_mtu(_socket: &UdpSocket) -> Option<u16> {
    info!("TODO: Implement this function for other platforms.");
    None
}
