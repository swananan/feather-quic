#[cfg(target_os = "linux")]
pub fn is_io_uring_supported() -> bool {
    true
}

#[cfg(not(target_os = "linux"))]
pub fn is_io_uring_supported() -> bool {
    false
} 