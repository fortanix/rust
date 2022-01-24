use crate::io::{self, ErrorKind, Read};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sys::net::TcpStream;
use crate::os::fd::raw::{IntoRawFd, RawFd};
use crate::fs::OpenOptions;
use fortanix_vme_abi::{Addr, Response, Request};
use libc::ioctl;
use nsm::{self, Nsm};
use nsm_driver::{self, DEV_FILE, NsmMessage};
use vsock::{self, Platform, VsockListener, VsockStream};

static INIT: AtomicBool = AtomicBool::new(false);
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
impl nsm_driver::Platform for Fortanixvme {
    fn open_dev() -> i32 {
        let mut open_options = OpenOptions::new();
        let open_dev = open_options.read(true).write(true).open(DEV_FILE);

        match open_dev {
            Ok(open_dev) => {
                open_dev.into_raw_fd() as i32
            }
            Err(e) => {
                eprintln!("Failed to open NSM driver");
                -1
            }
        }
    }

    fn nsm_ioctl(fd: i32, message: &mut NsmMessage) -> Option<i32> {
        // Reimplementation of `nix::request_code_readwrite` to avoid depending on the `nix` crate
        fn request_code_readwrite(ioctl_magic: u8, nr: libc::c_int, sz: usize) -> libc::c_int {
            const WRITE: u8 = 1;
            const READ: u8 = 2;
            const DIRMASK: libc::c_int = 3;
            const DIRSHIFT: libc::c_int = 30;
            const TYPEMASK: libc::c_int = 255;
            const TYPESHIFT: libc::c_int = 8;
            const NRMASK: libc::c_int = 255;
            const NRSHIFT: libc::c_int = 0;
            const SIZEMASK: libc::c_int = 16383;
            const SIZESHIFT: libc::c_int = 16;
            (((READ | WRITE) as libc::c_int & DIRMASK) << DIRSHIFT)
                | ((ioctl_magic as libc::c_int & TYPEMASK) << TYPESHIFT)
                | ((nr as libc::c_int & NRMASK) << NRSHIFT)
                | ((sz as libc::c_int & SIZEMASK) << SIZESHIFT)
        }
        let status = unsafe {
            ioctl(
                fd,
                request_code_readwrite(nsm_driver::NSM_IOCTL_MAGIC, 0, crate::mem::size_of::<NsmMessage>()),
                message,
            )
        };

        if status == 0 {
            // If ioctl() succeeded, the status is the message's response code
            None
        } else {
            // If ioctl() failed, the error is given by errno
            Some(super::super::os::errno() as i32)
        }
    }

    fn close_dev(fd: i32) {
        unsafe { libc::close(fd as RawFd); }
    }
}

fn init() -> Result<(), nsm::Error> {
    if !INIT.swap(true, Ordering::SeqCst) {
        let nsm = Nsm::<Fortanixvme>::new()?;
        nsm.lock_pcrs(24)?;
        Ok(())
    } else {
        Ok(())
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
        /// The local address the socket is bound to.
        local: Addr,
    },
    Stream {
        /// The local address the socket is bound to.
        local: Addr,
        /// The peer the socket is connected to.
        peer: Addr,
    },
}

impl ConnectionInfo {
    pub(crate) fn new_stream_info(local: Addr, peer: Addr) -> Self {
        ConnectionInfo::Stream {
            local,
            peer,
        }
    }

    pub(crate) fn new_listener_info(local: Addr) -> Self {
        ConnectionInfo::Listener {
            local,
        }
    }
}

pub struct Client {
    stream: VsockStream<Fortanixvme>,
}

impl Client {
    fn connect(port: u32) -> Result<VsockStream<Fortanixvme>, io::Error> {
        let vsock = VsockStream::connect_with_cid_port(vsock::VMADDR_CID_HOST, port)?;

        if let Err(_e) = init() {
            eprintln!("Failed to init Nitro Security Module");
        }
        Ok(vsock)
    }

    pub fn new(port: u32) -> Result<Self, io::Error> {
        Ok(Client {
            stream: Self::connect(port)?,
        })
    }

    pub fn open_proxy_connection(&mut self, addr: String) -> Result<(VsockStream<Fortanixvme>, Addr, Addr), io::Error> {
        let connect = Request::Connect {
            addr
        };
        self.send(&connect)?;
        if let Response::Connected { proxy_port, local, peer } = self.receive()? {
            let proxy = Self::connect(proxy_port)?;
            Ok((proxy, local, peer))
        } else {
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response received"))
        }
    }

    /// Bind a TCP socket in the parent VM to the specified address. Returns the `VsockListener`
    /// listening for incoming connections forwarded by the parent VM and the local address the runner
    /// is listening on
    pub fn bind_socket(&mut self, addr: String) -> Result<(VsockListener<Fortanixvme>, Addr), io::Error> {
        // Start listener socket within enclave, waiting for incoming connections from enclave
        // runner
        let listener = VsockListener::bind_with_cid(vsock::VMADDR_CID_ANY)?;
        let enclave_port = listener.local_addr()?.port();

        // Tell runner to start listening on the specified address and forward trafic to the
        // specified port
        let bind = Request::Bind {
            addr,
            enclave_port,
        };
        self.send(&bind)?;
        if let Response::Bound { local } = self.receive()? {
            Ok((listener, local))
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

    pub fn close_listener_socket(&mut self, enclave_port: u32) -> Result<(), io::Error> {
        let close = Request::Close {
            enclave_port
        };
        self.send(&close)?;

        if let Response::Closed = self.receive()? {
            Ok(())
        } else {
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response received"))
        }
    }

    pub(crate) fn info_listener(&mut self, enclave_port: u32) -> Result<ConnectionInfo, io::Error> {
        let info = Request::Info {
            enclave_port,
            runner_port: None,
        };
        self.send(&info)?;
        if let Response::Info { local, peer: None } = self.receive()? {
            Ok(ConnectionInfo::new_listener_info(local))
        } else {
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response"))
        }
    }

    pub(crate) fn info_connection(&mut self, enclave_port: u32, runner_port: u32) -> Result<ConnectionInfo, io::Error> {
        let info = Request::Info {
            enclave_port,
            runner_port: Some(runner_port),
        };
        self.send(&info)?;
        if let Response::Info { local, peer: Some(peer) } = self.receive()? {
            Ok(ConnectionInfo::new_stream_info(local, peer))
        } else {
            Err(io::Error::new(ErrorKind::InvalidData, "Unexpected response"))
        }
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
    }
}
