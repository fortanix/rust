use crate::collections::HashMap;
use crate::io::{self, ErrorKind, Read};
use crate::lazy::SyncOnceCell;
use crate::ops::Deref;
use crate::os::fd::raw::{AsRawFd, FromRawFd, RawFd};
use crate::sync::{Arc, RwLock};
use crate::sys::cvt;
use crate::sys::fd::FileDesc;
use fortanix_vme_abi::{self, Addr, Response, Request};
use vsock::{self, Platform, VsockListener, VsockStream};

const MIN_READ_BUFF: usize = 0x2000;

#[unstable(feature = "fortanixvme", issue = "none")]
pub struct Fortanixvme;

#[unstable(feature = "fortanixvme", issue = "none")]
impl Platform for Fortanixvme {
    fn last_os_error() -> vsock::Error {
        vsock::Error::SystemError(super::super::os::errno() as i32)
    }
}

// Compiler bug in nightly-2021-09-08-x86_64-unknown-linux-gnu requires both annotations
#[allow(ineffective_unstable_trait_impl)]
#[unstable(feature = "fortanixvme", issue = "none")]
impl crate::error::Error for vsock::Error {}

// Compiler bug in nightly-2021-09-08-x86_64-unknown-linux-gnu requires both annotations
#[allow(ineffective_unstable_trait_impl)]
#[unstable(feature = "fortanixvme", issue = "none")]
impl From<vsock::Error> for io::Error {
    fn from(err: vsock::Error) -> io::Error {
        match err {
            vsock::Error::EntropyError        => io::Error::new(ErrorKind::Other, err),
            vsock::Error::ReservedPort        => io::Error::new(ErrorKind::InvalidInput, err),
            vsock::Error::SystemError(errno)  => io::Error::from_raw_os_error(errno),
            vsock::Error::WrongAddressType    => io::Error::new(ErrorKind::InvalidInput, err),
            vsock::Error::ZeroDurationTimeout => io::Error::new(ErrorKind::InvalidInput, err),
        }
    }
}

#[unstable(feature = "fortanixvme", issue = "none")]
impl From<fortanix_vme_abi::ErrorKind> for io::ErrorKind {
    fn from(kind: fortanix_vme_abi::ErrorKind) -> io::ErrorKind {
        match kind {
            fortanix_vme_abi::ErrorKind::NotFound => io::ErrorKind::NotFound,
            fortanix_vme_abi::ErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
            fortanix_vme_abi::ErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            fortanix_vme_abi::ErrorKind::ConnectionReset => io::ErrorKind::ConnectionReset,
            fortanix_vme_abi::ErrorKind::HostUnreachable => io::ErrorKind::HostUnreachable,
            fortanix_vme_abi::ErrorKind::NetworkUnreachable => io::ErrorKind::NetworkUnreachable,
            fortanix_vme_abi::ErrorKind::ConnectionAborted => io::ErrorKind::ConnectionAborted,
            fortanix_vme_abi::ErrorKind::NotConnected => io::ErrorKind::NotConnected,
            fortanix_vme_abi::ErrorKind::AddrInUse => io::ErrorKind::AddrInUse,
            fortanix_vme_abi::ErrorKind::AddrNotAvailable => io::ErrorKind::AddrNotAvailable,
            fortanix_vme_abi::ErrorKind::NetworkDown => io::ErrorKind::NetworkDown,
            fortanix_vme_abi::ErrorKind::BrokenPipe => io::ErrorKind::BrokenPipe,
            fortanix_vme_abi::ErrorKind::AlreadyExists => io::ErrorKind::AlreadyExists,
            fortanix_vme_abi::ErrorKind::WouldBlock => io::ErrorKind::WouldBlock,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::NotADirectory => io::ErrorKind::NotADirectory,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::IsADirectory => io::ErrorKind::IsADirectory,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::DirectoryNotEmpty => io::ErrorKind::DirectoryNotEmpty,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::ReadOnlyFilesystem => io::ErrorKind::ReadOnlyFilesystem,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::FilesystemLoop => io::ErrorKind::FilesystemLoop,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::StaleNetworkFileHandle => io::ErrorKind::StaleNetworkFileHandle,
            fortanix_vme_abi::ErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
            fortanix_vme_abi::ErrorKind::InvalidData => io::ErrorKind::InvalidData,
            fortanix_vme_abi::ErrorKind::TimedOut => io::ErrorKind::TimedOut,
            fortanix_vme_abi::ErrorKind::WriteZero => io::ErrorKind::WriteZero,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::StorageFull => io::ErrorKind::StorageFull,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::NotSeekable => io::ErrorKind::NotSeekable,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::FilesystemQuotaExceeded => io::ErrorKind::FilesystemQuotaExceeded,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::FileTooLarge => io::ErrorKind::FileTooLarge,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::ResourceBusy => io::ErrorKind::ResourceBusy,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::ExecutableFileBusy => io::ErrorKind::ExecutableFileBusy,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::Deadlock => io::ErrorKind::Deadlock,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::CrossesDevices => io::ErrorKind::CrossesDevices,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::TooManyLinks => io::ErrorKind::TooManyLinks,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::FilenameTooLong => io::ErrorKind::FilenameTooLong,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            fortanix_vme_abi::ErrorKind::ArgumentListTooLong => io::ErrorKind::ArgumentListTooLong,
            fortanix_vme_abi::ErrorKind::Interrupted => io::ErrorKind::Interrupted,
            fortanix_vme_abi::ErrorKind::Unsupported => io::ErrorKind::Unsupported,
            fortanix_vme_abi::ErrorKind::UnexpectedEof => io::ErrorKind::UnexpectedEof,
            fortanix_vme_abi::ErrorKind::OutOfMemory => io::ErrorKind::OutOfMemory,
            fortanix_vme_abi::ErrorKind::Other => io::ErrorKind::Other,
            //#[unstable(feature = "io_error_uncategorized", issue = "none")]
            fortanix_vme_abi::ErrorKind::Uncategorized => io::ErrorKind::Uncategorized,
        }
    }
}

#[unstable(feature = "fortanixvme", issue = "none")]
impl Read for VsockStream<Fortanixvme> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        VsockStream::<Fortanixvme>::read(&mut &*self, buf).map_err(|e| e.into())
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ConnectionInfo {
    Listener {
        /// The local address (of the runner) the socket is bound to
        local: Addr,
        /// The vsock port the enclave is listening on to receive connections from the runner
        enclave_port: u32,
    },
    Stream {
        /// The vsock port the enclave is using to communicate with the runner
        enclave_port: u32,
        /// The local address the socket is bound to.
        local: Addr,
        /// The peer the socket is connected to.
        peer: Addr,
    },
}

impl ConnectionInfo {
    pub(crate) fn new_stream_info(enclave_port: u32, local: Addr, peer: Addr) -> Self {
        ConnectionInfo::Stream {
            enclave_port,
            local,
            peer,
        }
    }

    pub(crate) fn new_listener_info(local: Addr, enclave_port: u32) -> Self {
        ConnectionInfo::Listener {
            local,
            enclave_port,
        }
    }

    pub fn enclave_port(&self) -> u32 {
        match self {
            ConnectionInfo::Listener { enclave_port, .. } => *enclave_port,
            ConnectionInfo::Stream { enclave_port, .. }   => *enclave_port,
        }
    }
}

pub(crate) struct ConnectionGuard(ConnectionInfo);

impl Deref for ConnectionGuard {
    type Target = ConnectionInfo;

    fn deref(&self) -> &ConnectionInfo {
        &self.0
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        println!("[{}:{}] Dropping connection", file!(), line!());
        let _ = Client::close_connection(self.enclave_port());
    }
}

pub struct Client {
    stream: VsockStream<Fortanixvme>,
}

impl Client {
    // TODO Use the FNV crate for the Fowler–Noll–Vo hash function for better performance (requires upstream changes).
    fn connection_info_map() -> &'static RwLock<HashMap<RawFd, Arc<ConnectionGuard>>> {
        println!("{}:{} connection_info_map", file!(), line!());
        static CONNECTION_INFO: SyncOnceCell<RwLock<HashMap<RawFd, Arc<ConnectionGuard>>>> = SyncOnceCell::new();
        CONNECTION_INFO.get_or_init(|| RwLock::new(HashMap::new()))
    }

    pub(crate) fn store_connection_info<FD: AsRawFd>(fd: &FD, info: ConnectionInfo) {
        println!("{}:{} store connection info", file!(), line!());
        let raw_fd = fd.as_raw_fd();
        println!("{}:{} store connection info", file!(), line!());
        let mut map = Self::connection_info_map().write().expect("ConnectionInfo RwLock poisoned");
        println!("{}:{} store connection info", file!(), line!());
        if let Some(_prev) = map.insert(raw_fd, Arc::new(ConnectionGuard(info))) {
            println!("{}:{} store connection info", file!(), line!());
            eprintln!("panic! Already keeping track of Connection info related to file descriptor {}", raw_fd);
        }
    }

    pub(crate) fn remove_connection_info<FD: AsRawFd>(fd: &FD) {
        println!("[{}:{}] Removing connection info", file!(), line!());
        let raw_fd = fd.as_raw_fd();
        println!("[{}:{}] Removing connection info", file!(), line!());
        let mut map = Self::connection_info_map().write().expect("ConnectionInfo RwLock poisoned");
        println!("[{}:{}] Removing connection info", file!(), line!());
        map.remove(&raw_fd);
        println!("[{}:{}] Removing connection info", file!(), line!());
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

    pub(crate) fn connection_info<FD: AsRawFd>(fd: &FD) -> Option<Arc<ConnectionGuard>> {
        println!("[{}:{}] connection_info", file!(), line!());
        let raw_fd = fd.as_raw_fd();
        Self::connection_info_map()
            .read()
            .expect("ConnectionInfo RwLock poisoned")
            .get(&raw_fd)
            .cloned()
    }

    pub fn duplicate_fd(fd: RawFd) -> io::Result<RawFd> {
        println!("[{}:{}] duplicate fd", file!(), line!());
        let dup = cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) })?;
        println!("[{}:{}] duplicate fd", file!(), line!());
        assert!(dup != fd);
        println!("[{}:{}] duplicate fd", file!(), line!());
        let mut map = Self::connection_info_map()
            .write()
            .expect("ConnectionInfo RwLock poisoned");
        println!("[{}:{}] duplicate fd", file!(), line!());
        let info = map.get(&fd)
            .ok_or(io::Error::from(io::ErrorKind::InvalidData))?
            .clone();
        println!("[{}:{}] duplicate fd", file!(), line!());
        if map.insert(dup, info).is_none() {
            eprintln!("panic! Connection info still exists");
        }
        println!("[{}:{}] duplicate fd", file!(), line!());
        Ok(dup)
    }

    fn connect(port: u32) -> Result<VsockStream<Fortanixvme>, io::Error> {
        // Try to contact the enclave runner through the hypervisor
        VsockStream::connect_with_cid_port(vsock::VMADDR_CID_HOST, port)
            .or_else(|e0| {
                // When debugging, there may not be a hypervisor. Fall back to local communication
                // on the same host.
                VsockStream::connect_with_cid_port(vsock::VMADDR_CID_LOCAL, port)
                    .map_err(|_e1| io::Error::new(ErrorKind::InvalidData, e0))
            })
    }

    pub fn new(port: u32) -> Result<Self, io::Error> {
        Ok(Client {
            stream: Self::connect(port)?,
        })
    }

    pub fn open_proxy_connection(&mut self, addr: String) -> Result<FileDesc, io::Error> {
        let connect = Request::Connect {
            addr
        };
        self.send(&connect)?;
        if let Response::Connected { proxy_port, local, peer } = self.receive()? {
            let proxy = Self::connect(proxy_port)?;
            let enclave_port = proxy.local_addr()?.port();
            let fd = unsafe { FromRawFd::from_raw_fd(proxy.into_raw_fd()) };
            let info = ConnectionInfo::new_stream_info(enclave_port, local, peer);
            Client::store_connection_info(&fd, info);
            Ok(fd)
        } else {
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response received"))
        }
    }

    /// Bind a TCP socket in the parent VM to the specified address. Returns a Socket
    /// listening for incoming connections forwarded by the parent VM
    pub fn bind_socket(&mut self, addr: String) -> Result<FileDesc, io::Error> {
        // Start listener socket within enclave, waiting for incoming connections from enclave
        // runner
        let listener = VsockListener::<Fortanixvme>::bind_with_cid(vsock::VMADDR_CID_ANY)?;
        let enclave_port = listener.local_addr()?.port();

        // Tell runner to start listening on the specified address and forward trafic to the
        // specified port
        let bind = Request::Bind {
            addr,
            enclave_port,
        };
        self.send(&bind)?;
        if let Response::Bound { local } = self.receive()? {
            let fd = unsafe { FromRawFd::from_raw_fd(listener.into_raw_fd()) };
            let info = ConnectionInfo::new_listener_info(local, enclave_port);
            Self::store_connection_info(&fd, info);
            Ok(fd)
        } else {
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response received"))
        }
    }

    pub fn accept(&mut self, vsock_port: u32) -> Result<(Addr, Addr, u32), io::Error> {
        let accept = Request::Accept {
            enclave_port: vsock_port
        };
        self.send(&accept)?;

        if let Response::IncomingConnection { local, peer, proxy_port } = self.receive()? {
            Ok((local, peer, proxy_port))
        } else {
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response received"))
        }
    }

    fn close_connection(enclave_port: u32) -> Result<(), io::Error> {
        println!("[{}:{}] close connection", file!(), line!());
        let mut client = Self::new(fortanix_vme_abi::SERVER_PORT)?;
        println!("[{}:{}] close connection", file!(), line!());

        let close = Request::Close {
            enclave_port,
        };
        println!("[{}:{}] close connection", file!(), line!());
        client.send(&close)?;
        println!("[{}:{}] close connection", file!(), line!());

        if let Response::Closed = client.receive()? {
            println!("[{}:{}] close connection", file!(), line!());

            Ok(())
        } else {
            println!("[{}:{}] close connection", file!(), line!());
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response received"))
        }
    }

    pub(crate) fn args() -> Result<Vec<String>, io::Error> {
        let mut client = Self::new(fortanix_vme_abi::SERVER_PORT)?;
        client.send(&Request::Init)?;
        let r = client.receive()?;
        if let Response::Init { args } = r {
            println!("{}:{} args", file!(), line!());
            Ok(args)
        } else {
            println!("{}:{} args", file!(), line!());
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response"))
        }
    }

    pub(crate) fn exit(code: i32) -> ! {
        let _ = Self::new(fortanix_vme_abi::SERVER_PORT)
            .and_then(|mut client| {
                client.send(&Request::Exit {
                    code
                })
            });

        // Failed to connect to the runner, stop the enclave anyway
        unsafe { libc::exit(code as libc::c_int) }
    }

    fn send(&mut self, req: &Request) -> Result<(), io::Error> {
        let req: Vec<u8> = serde_cbor::ser::to_vec(req).map_err(|_e| io::Error::new(ErrorKind::Other, "serialization failed"))?;
        self.stream.write(req.as_slice())?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Response, io::Error> {
        // We'd like to have used a streaming deserializer. Unfortunately, that implies that we
        // are able to create a `Deserializer` from a reader (i.e., the socket). Unfortunately
        // that requires enabling the std feature of serde_cbor and that's obvious not possible
        fn read<P: Platform>(stream: &mut VsockStream<P>, mut buff: Vec<u8>) -> Result<Response, io::Error> {
            let old_size = buff.len();
            let new_size = crate::cmp::max(old_size.next_power_of_two(), MIN_READ_BUFF);
            buff.resize(new_size, 0);
            let n = stream.read(&mut buff[old_size..])?;
            buff.truncate(old_size + n);

            match serde_cbor::from_slice(buff.as_slice()) {
                Ok(resp)  => Ok(resp),
                Err(e)    => if e.is_eof() {
                        read(stream, buff)
                    } else {
                        Err(io::Error::new(ErrorKind::InvalidData, "Deserialization failed"))
                    },
            }
        }
        read(&mut self.stream, Vec::new())
            .map(|resp| match resp {
                fortanix_vme_abi::Response::Failed(fortanix_vme_abi::Error::Command(kind)) => Err(io::Error::from(io::ErrorKind::from(kind))),
                fortanix_vme_abi::Response::Failed(fortanix_vme_abi::Error::SystemError(errno)) => Err(io::Error::from_raw_os_error(errno as _)),
                other => Ok(other),
            })?
    }
}
