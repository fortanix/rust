use enclave_runner_client::{ConnectionInfo};

use crate::collections::HashMap;
use crate::io::{self};
use crate::ops::Deref;
use crate::os::fd::raw::{AsRawFd, RawFd};
use crate::sync::{Arc, OnceLock, RwLock};
use crate::sys::cvt;
use crate::sys::fortanixvme::client::RunnerClient;

pub struct ConnectionGuard(ConnectionInfo);

impl Deref for ConnectionGuard {
    type Target = ConnectionInfo;

    fn deref(&self) -> &ConnectionInfo {
        &self.0
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let _ = RunnerClient::close_connection(self.enclave_port());
    }
}


pub struct ConnectionRegistry;

impl ConnectionRegistry {
    // FIXME: Use the FNV crate for the Fowler–Noll–Vo hash function for better performance (requires upstream changes).
    fn map() -> &'static RwLock<HashMap<RawFd, Arc<ConnectionGuard>>> {
        static CONNECTION_INFO: OnceLock<RwLock<HashMap<RawFd, Arc<ConnectionGuard>>>> =
            OnceLock::new();
        CONNECTION_INFO.get_or_init(|| RwLock::new(HashMap::new()))
    }

    pub fn insert<FD: AsRawFd>(fd: &FD, info: ConnectionInfo) {
        let raw_fd = fd.as_raw_fd();
        let mut map = Self::map().write().expect("ConnectionInfo RwLock poisoned");
        if let Some(_prev) = map.insert(raw_fd, Arc::new(ConnectionGuard(info))) {
            eprintln!(
                "panic! Already keeping track of Connection info related to file descriptor {}",
                raw_fd
            );
        }
    }

    pub fn remove<FD: AsRawFd>(fd: &FD) {
        let raw_fd = fd.as_raw_fd();
        let mut map = Self::map().write().expect("ConnectionInfo RwLock poisoned");
        let info = map.remove(&raw_fd);
        // Instruct the runner to close the connection nicely, before we close it in the enclave to
        // ensure file descriptors and ports won't be reused before existing references are cleaned
        // up in the runner.
        drop(info);
        unsafe {
            // Now there's no mapping anymore, we can close the actual fd
            // Note that errors are ignored when closing a file descriptor. The
            // reason for this is that if an error occurs we don't actually know if
            // the file descriptor was closed or not, and if we retried (for
            // something like EINTR), we might close another valid file descriptor
            // opened after we closed ours.
            let _ = libc::close(raw_fd);
        }
    }

    pub fn get<FD: AsRawFd>(fd: &FD) -> Option<Arc<ConnectionGuard>> {
        let raw_fd = fd.as_raw_fd();
        Self::map()
            .read()
            .expect("ConnectionInfo RwLock poisoned")
            .get(&raw_fd)
            .cloned()
    }

    pub fn duplicate_fd(fd: RawFd) -> io::Result<RawFd> {
        let mut map = Self::map().write().expect("ConnectionInfo RwLock poisoned");
        let info = map.get(&fd).ok_or(io::Error::from(io::ErrorKind::InvalidData))?.clone();
        let dup = cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) })?;
        assert!(dup != fd);
        if map.insert(dup, info).is_some() {
            panic!("Connection info still exists");
        }
        Ok(dup)
    }
}
