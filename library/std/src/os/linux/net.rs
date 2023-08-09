//! Linux-specific networking functionality.

#![stable(feature = "unix_socket_abstract", since = "1.70.0")]

// #[cfg(not(all(target_arch = "x86_64", target_os = "linux", target_env = "fortanixvme")))]
#[stable(feature = "unix_socket_abstract", since = "1.70.0")]
pub use crate::os::net::linux_ext::addr::SocketAddrExt;

// #[cfg(not(all(target_arch = "x86_64", target_os = "linux", target_env = "fortanixvme")))]
#[unstable(feature = "tcp_quickack", issue = "96256")]
pub use crate::os::net::linux_ext::tcp::TcpStreamExt;
