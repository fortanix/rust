use crate::fmt::{self, Display, Formatter};
use crate::io::{self, ErrorKind, Read};
use fortanix_vme_abi::{Addr, Response, Request};
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

#[derive(Debug)]
struct VsockErrorWrapper(vsock::Error);

// Compiler bug in nightly-2021-09-08-x86_64-unknown-linux-gnu requires both annotations
#[allow(ineffective_unstable_trait_impl)]
#[unstable(feature = "fortanixvme", issue = "none")]
impl crate::error::Error for VsockErrorWrapper {}

impl Display for VsockErrorWrapper {
     fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
         self.0.fmt(f)
     }
}

impl From<vsock::Error> for VsockErrorWrapper {
    fn from(e: vsock::Error) -> VsockErrorWrapper {
        VsockErrorWrapper(e)
    }
}

// Compiler bug in nightly-2021-09-08-x86_64-unknown-linux-gnu requires both annotations
#[allow(ineffective_unstable_trait_impl)]
#[unstable(feature = "fortanixvme", issue = "none")]
impl From<vsock::Error> for io::Error {
    fn from(err: vsock::Error) -> io::Error {
        match err {
            vsock::Error::EntropyError        => io::Error::new(ErrorKind::Other, VsockErrorWrapper::from(err)),
            vsock::Error::ReservedPort        => io::Error::new(ErrorKind::InvalidInput, VsockErrorWrapper::from(err)),
            vsock::Error::SystemError(errno)  => io::Error::from_raw_os_error(errno),
            vsock::Error::WrongAddressType    => io::Error::new(ErrorKind::InvalidInput, VsockErrorWrapper::from(err)),
            vsock::Error::ZeroDurationTimeout => io::Error::new(ErrorKind::InvalidInput, VsockErrorWrapper::from(err)),
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
        // Try to contact the enclave runner through the hypervisor
        VsockStream::connect_with_cid_port(vsock::VMADDR_CID_HOST, port)
            .or_else(|e0| {
                // When debugging, there may not be a hypervisor. Fall back to local communication
                // on the same host.
                VsockStream::connect_with_cid_port(vsock::VMADDR_CID_LOCAL, port)
                    .map_err(|_e1| io::Error::new(ErrorKind::InvalidData, VsockErrorWrapper::from(e0)))
            })
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
    }
}
