//! Linux-specific definitions.

#![stable(feature = "raw_ext", since = "1.1.0")]
#![doc(cfg(target_os = "linux"))]

pub mod fs;
#[cfg(not(all(target_arch = "x86_64", target_os = "linux", target_env = "fortanixvme")))]
pub mod net;
pub mod process;
pub mod raw;
