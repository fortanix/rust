use core::convert::TryFrom;
use crate::io::{self, ErrorKind, IoSlice, IoSliceMut};
use crate::lazy::SyncOnceCell;
use crate::sync::Mutex;
use crate::sys::fd::FileDesc;
use crate::sys_common::{FromInner, IntoInner};
use crate::time::Duration;
use crate::fmt;
use crate::mem;
use crate::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use crate::ops::Deref;
use crate::os::fd::raw::AsRawFd;
use crate::os::fd::owned::{AsFd, BorrowedFd};
use crate::os::unix::prelude::{IntoRawFd, FromRawFd, RawFd};
use crate::sys::{cvt, cvt_r};
use crate::sys_common::AsInner;
use fortanix_vme_abi::{self, Addr};
use libc::{self, c_int, c_void, MSG_PEEK};
use super::client::{Client, ConnectionInfo, Fortanixvme};
use vsock::{SockAddr as VsockAddr};

pub(crate) extern crate libc as netc;

#[derive(Debug)]
struct NonIpSockAddr {
    host: String,
}

impl NonIpSockAddr {
    pub fn new(host: String) -> NonIpSockAddr {
        NonIpSockAddr {
            host: host,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }
}

impl crate::error::Error for NonIpSockAddr {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "Failed to convert address to SocketAddr"
    }
}

impl fmt::Display for NonIpSockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to convert address to SocketAddr: {}", self.host)
    }
}

pub(crate) struct LookupHost(!);

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        None
    }
}

impl LookupHost {
    pub fn port(&self) -> u16 {
        self.0
    }
}

unsafe impl Sync for LookupHost {}
unsafe impl Send for LookupHost {}

impl TryFrom<&str> for LookupHost {
    type Error = io::Error;

    fn try_from(v: &str) -> io::Result<LookupHost> {
        Err(io::Error::new(io::ErrorKind::Uncategorized, NonIpSockAddr::new(v.to_string())))
    }
}

impl<'a> TryFrom<(&'a str, u16)> for LookupHost {
    type Error = io::Error;

    fn try_from(v: (&'a str, u16)) -> io::Result<LookupHost> {
        let host = format!("{}:{}", v.0, v.1);
        Err(io::Error::new(io::ErrorKind::Uncategorized, NonIpSockAddr::new(host)))
    }
}

fn io_err_to_addr(result: io::Result<&SocketAddr>) -> io::Result<String> {
    match result {
        Ok(saddr) => Ok(saddr.to_string()),
        Err(e) => {
            e.get_ref().and_then(|e| if let Some(addr) = e.downcast_ref::<NonIpSockAddr>() {
                Some(addr.host().to_owned())
            } else {
                None
            }).ok_or(e)
        }
    }
}

fn getsockopt<T: Copy>(fd: RawFd, opt: c_int, val: c_int) -> io::Result<T> {
    unsafe {
        let mut slot: T = mem::zeroed();
        let mut len = mem::size_of::<T>() as libc::socklen_t;
        cvt(libc::getsockopt(fd, opt, val, &mut slot as *mut _ as *mut _, &mut len))?;
        assert_eq!(len as usize, mem::size_of::<T>());
        Ok(slot)
    }
}

macro_rules! not_available {
    () => {
        return Err(io::Error::new_const(
            io::ErrorKind::Unsupported,
            &"Not available on Fortanixvme",
        ))
    };
}

#[derive(Clone, Debug)]
struct IncomingInfo {
    local: Addr,
    peer: Addr,
    runner_port: u32,
}
static INCOMING_INFO: SyncOnceCell<Mutex<Vec<IncomingInfo>>> = SyncOnceCell::new();

fn incoming_info() -> &'static Mutex<Vec<IncomingInfo>> {
    INCOMING_INFO.get_or_init(|| Mutex::new(Vec::new()))
}

fn store_incoming_connection_info(info: IncomingInfo) {
    incoming_info().lock().unwrap().push(info)
}

fn take_incoming_connection_info(runner_port: u32) -> Option<IncomingInfo> {
    let info = incoming_info();
    let mut info = info.lock().unwrap();
    info.iter()
        .enumerate()
        .find_map(|(idx, info)| {
            if info.runner_port == runner_port {
                Some(idx)
            } else {
                None
            }
        })
        .map(|idx| info.remove(idx))
}

pub struct Socket {
    inner: FileDesc,
}

impl Socket {
    fn new(fd: FileDesc) -> Self {
        Socket {
            inner: fd,
        }
    }

    pub fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        // ineffective
        Ok(())
    }

    pub fn duplicate(&self) -> io::Result<Socket> {
        Ok(Socket {
            inner: self.inner.duplicate()?,
        })
    }

    fn recv_with_flags(&self, buf: &mut [u8], flags: c_int) -> io::Result<usize> {
        let ret = cvt(unsafe {
            libc::recv(self.as_raw_fd(), buf.as_mut_ptr() as *mut c_void, buf.len(), flags)
        })?;
        Ok(ret as usize)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, 0)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.inner.read_vectored(bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        self.inner.is_read_vectored()
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, MSG_PEEK)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.inner.write_vectored(bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let raw: c_int = getsockopt(self.as_raw(), libc::SOL_SOCKET, libc::SO_ERROR)?;
        if raw == 0 { Ok(None) } else { Ok(Some(io::Error::from_raw_os_error(raw as i32))) }
    }

    // This is used by sys_common code to abstract over Windows and Unix.
    pub fn as_raw(&self) -> RawFd {
        self.as_raw_fd()
    }

    pub fn accept(&self, storage: *mut libc::sockaddr, len: *mut libc::socklen_t) -> io::Result<Socket> {
        // Unfortunately the only known way right now to accept a socket and
        // atomically set the CLOEXEC flag is to use the `accept4` syscall on
        // platforms that support it. On Linux, this was added in 2.6.28,
        // glibc 2.10 and musl 0.9.5.
        unsafe {
            let fd = cvt_r(|| libc::accept4(self.as_raw_fd(), storage, len, libc::SOCK_CLOEXEC))?;
            Ok(Socket {
                inner: FileDesc::from_raw_fd(fd),
            })
        }
    }
}

impl FromInner<FileDesc> for Socket {
    fn from_inner(fd: FileDesc) -> Socket {
        Socket {
            inner: fd,
        }
    }
}


impl IntoInner<FileDesc> for Socket {
    fn into_inner(self) -> FileDesc {
        self.inner
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

impl FromRawFd for Socket {
    unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
        Socket {
            inner: FromRawFd::from_raw_fd(raw_fd),
        }
    }
}

pub struct TcpStream {
    pub(crate) inner: Socket,
}

impl TcpStream {
    pub fn connect(addr: io::Result<&SocketAddr>) -> io::Result<TcpStream> {
        let addr = io_err_to_addr(addr)?;
        let mut runner = Client::new(fortanix_vme_abi::SERVER_PORT)?;
        let fd = runner.open_proxy_connection(addr.clone())?;
        Ok(TcpStream {
            inner: Socket::new(fd),
        })
    }

    pub fn connect_timeout(_addr: &SocketAddr, _timeout: Duration) -> io::Result<TcpStream> {
        not_available!()
    }

    pub fn socket(&self) -> &Socket {
        &self.inner
    }

    pub fn into_socket(self) -> Socket {
        self.inner
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        if dur == Some(Duration::default()) {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot set a 0 duration timeout"))
        } else {
            // PLAT-368 provide proper implementation
            Ok(())
        }
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        if dur == Some(Duration::default()) {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot set a 0 duration timeout"))
        } else {
            // PLAT-368 provide proper implementation
            Ok(())
        }
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        not_available!()
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        not_available!()
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.inner.read_vectored(bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        self.inner.is_read_vectored()
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.inner.write_vectored(bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    /// Returns the address of the peer.
    ///
    /// # Warning
    ///
    /// There is no guarantee that the `TcpStream` actually communicates with the returned `SocketAddr`.
    /// Users should rely on additional security mechanisms such as TLS.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        println!("{}:{} peer_addr", file!(), line!());
        if let Some(ConnectionInfo::Stream{ peer, .. }) = Client::connection_info(&self.inner).as_deref().map(|guard| guard.deref()) {
            println!("{}:{} peer_addr", file!(), line!());
            Ok(addr_to_sockaddr(peer.clone()))
        } else {
            println!("{}:{} peer_addr", file!(), line!());
            Err(io::Error::new(ErrorKind::AddrNotAvailable, "Unexpected connection info"))
        }
    }

    /// Returns the local address.
    ///
    /// # Warning
    ///
    /// There is no guarantee that the `TcpStream` actually communicates from the `SocketAddr`.
    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        println!("{}:{} socket_addr", file!(), line!());
        if let Some(ConnectionInfo::Stream{ local, .. }) = Client::connection_info(&self.inner).as_deref().map(|guard| guard.deref()) {
            println!("{}:{} socket_addr", file!(), line!());
            Ok(addr_to_sockaddr(local.clone()))
        } else {
            println!("{}:{} socket_addr", file!(), line!());
            Err(io::Error::new(ErrorKind::AddrNotAvailable, "Unexpected connection info"))
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    pub fn duplicate(&self) -> io::Result<TcpStream> {
        self.inner.duplicate().map(|s| TcpStream { inner: s })
    }

    pub fn set_linger(&self, _linger: Option<Duration>) -> io::Result<()> {
        not_available!()
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        not_available!()
    }

    pub fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        not_available!()
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        not_available!()
    }

    pub fn set_ttl(&self, _ttl: u32) -> io::Result<()> {
        not_available!()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        not_available!()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        not_available!()
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpStream").field("fd", &self.inner.as_raw_fd()).finish()
    }
}

impl FromInner<Socket> for TcpStream {
    fn from_inner(inner: Socket) -> TcpStream {
        TcpStream { inner }
    }
}

fn addr_to_sockaddr(addr: Addr) -> SocketAddr {
    fn hton16(x: u16) -> u16 {
        u16::from_be(x)
    }

    fn hton32(x: u32) -> u32 {
        u32::from_be(x)
    }

    match addr {
        Addr::IPv4 { port, ip } => {
            unsafe {
                let mut storage: libc::sockaddr_storage = mem::zeroed();
                let sockaddr = &mut storage as *const _ as *mut libc::sockaddr_in;
                (*sockaddr).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sockaddr).sin_port = hton16(port);
                (*sockaddr).sin_addr = libc::in_addr { s_addr: u32::from_le_bytes(ip) as libc::in_addr_t };
                assert!(mem::size_of::<libc::sockaddr_in>() <= mem::size_of::<libc::sockaddr_storage>());
                SocketAddr::V4(FromInner::from_inner(*sockaddr))
            }
        }
        Addr::IPv6 { ip, port, flowinfo, scope_id } => {
            unsafe {
                let mut storage: libc::sockaddr_storage = mem::zeroed();
                let sockaddr = &mut storage as *const _ as *mut libc::sockaddr_in6;
                (*sockaddr).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sockaddr).sin6_port = hton16(port);
                (*sockaddr).sin6_flowinfo = hton32(flowinfo);
                (*sockaddr).sin6_addr = libc::in6_addr { s6_addr: ip };
                (*sockaddr).sin6_scope_id = hton32(scope_id);
                assert!(mem::size_of::<libc::sockaddr_in6>() <= mem::size_of::<libc::sockaddr_storage>());
                SocketAddr::V6(FromInner::from_inner(*sockaddr))
            }
        }
    }
}

impl IntoRawFd for TcpStream {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

pub struct TcpListener {
    inner: Socket,
}

impl TcpListener {
    pub fn bind(addr: io::Result<&SocketAddr>) -> io::Result<TcpListener> {
        let addr = io_err_to_addr(addr)?;
        let mut runner = Client::new(fortanix_vme_abi::SERVER_PORT)?;
        let fd = runner.bind_socket(addr)?;
        Ok(TcpListener {
            inner: Socket::new(fd),
            })
    }

    pub fn socket(&self) -> &Socket {
        &self.inner
    }

    pub fn into_socket(self) -> Socket {
        self.inner
    }

    fn local_addr(&self) -> io::Result<Addr> {
        println!("{}:{} local_addr", file!(), line!());
        if let Some(ConnectionInfo::Listener{ local, .. }) = Client::connection_info(&self.inner).as_deref().map(|guard| guard.deref()) {
            println!("{}:{} local_addr", file!(), line!());
            Ok(local.clone())
        } else {
            println!("{}:{} local_addr", file!(), line!());
            Err(io::Error::new(ErrorKind::AddrNotAvailable, "Unexpected connection info"))
        }
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
            .map(|addr| addr_to_sockaddr(addr))
    }

    fn local_vsock_addr(&self) -> io::Result<VsockAddr> {
        // It would've been cleaner to provide a way to turn `self.inner` into a `VsockListener`
        // but we need to ensure that the `VsockListener` isn't dropped after the local address is
        // retrieved.
        let fd = self.inner.as_raw_fd();
        VsockAddr::from_raw_fd::<Fortanixvme>(fd).map_err(|e| e.into())
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        /* +-----------+
         * |   remote  |
         * +-----------+
         *       ^
         *       |
         *      TCP
         *       | (1) Accept new connection
         *       v
         * +----[ ]-----+            +-------------+
         * |   Runner   |            |   enclave   | (2) store peer/runner_port mapping
         * +--[ ]--[ ]--+            +-[ ]----[ ]--+
         *     \    \-----  enclave ----/      / (3) Accept new incoming connection from runner
         *      \-------- proxy --------------/
         */
        let local = self.local_vsock_addr()?;
        // (1) Tell the runner to accept an incoming connection on a specific port.
        let mut runner = Client::new(fortanix_vme_abi::SERVER_PORT)?;
        // When `accept` returns, the runner has accepted a new connection for peer. It will try
        // to connect to the enclave from `runner_port`
        let (local, peer, runner_port) = runner.accept(local.port())?;
        // Small optimization: No need to keep the connection to the runner while we wait for an
        // incoming vsock connection in step 3
        drop(runner);

        // (2) Store a mapping `runner_port` -> `peer`, where `runner_port` is the port the runner
        // will connect to the enclave in (3). `peer` is the address of the
        // remote client trying to connect to the enclave
        store_incoming_connection_info(IncomingInfo{ local, peer, runner_port });

        // (3) Accept the incoming connection from the runner
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as libc::socklen_t;
        let sock_runner = self.inner.accept(&mut storage as *mut _ as *mut _, &mut len)?.inner;
        // Find the previously stored peer address. Unfortunately, we need to store it in a
        // global variable and fetch it here again because of a subtle race condition. When
        // multiple clients are trying to connect on the same port, the peer address received
        // in (2), may not be the one proxied through the incoming connection.
        // TODO simplify solution by letting the runner start a vsock listener in (1) and
        // connecting to that listener after the `accept` returned.
        let runner_addr = &mut storage as *const _ as *mut libc::sockaddr_vm;
        let runner_addr = unsafe { VsockAddr::try_from(*runner_addr).expect("Vsock connection") };
        let IncomingInfo{ local, peer, .. } = take_incoming_connection_info(runner_addr.port())
            .ok_or(io::Error::new(ErrorKind::Other, "Internal error"))?;

        let info = ConnectionInfo::new_stream_info(runner_port, local, peer.clone());
        Client::store_connection_info(&sock_runner, info);
        let sock_runner = Socket::new(sock_runner);
        Ok((TcpStream { inner: sock_runner }, addr_to_sockaddr(peer)))
    }

    pub fn duplicate(&self) -> io::Result<TcpListener> {
        self.inner.duplicate().map(|s| TcpListener { inner: s })
    }

    pub fn set_ttl(&self, _ttl: u32) -> io::Result<()> {
        not_available!()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        not_available!()
    }

    pub fn set_only_v6(&self, _only_v6: bool) -> io::Result<()> {
        not_available!()
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        not_available!()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        not_available!()
    }

    pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        not_available!()
    }
}

impl FromInner<Socket> for TcpListener {
    fn from_inner(socket: Socket) -> TcpListener {
        TcpListener { inner: socket }
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = f.debug_struct("TcpListener");

        if let Ok(ref addr) = self.local_addr() {
            res.field("addr", addr);
        }

        res.field("fd", &self.inner.inner.as_inner()).finish()
    }
}
    
pub struct UdpSocket {
    inner: Socket,
}

impl UdpSocket {
    pub fn bind(_: io::Result<&SocketAddr>) -> io::Result<UdpSocket> {
        not_available!();
    }

    pub fn socket(&self) -> &Socket {
        &self.inner
    }

    pub fn into_socket(self) -> Socket {
        self.inner
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        not_available!();
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        not_available!();
    }

    pub fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        not_available!();
    }

    pub fn peek_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        not_available!();
    }

    pub fn send_to(&self, _: &[u8], _: &SocketAddr) -> io::Result<usize> {
        not_available!();
    }

    pub fn duplicate(&self) -> io::Result<UdpSocket> {
        not_available!();
    }

    pub fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        not_available!();
    }

    pub fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        not_available!();
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        not_available!();
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        not_available!();
    }

    pub fn set_broadcast(&self, _: bool) -> io::Result<()> {
        not_available!();
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        not_available!();
    }

    pub fn set_multicast_loop_v4(&self, _: bool) -> io::Result<()> {
        not_available!();
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        not_available!();
    }

    pub fn set_multicast_ttl_v4(&self, _: u32) -> io::Result<()> {
        not_available!();
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        not_available!();
    }

    pub fn set_multicast_loop_v6(&self, _: bool) -> io::Result<()> {
        not_available!();
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        not_available!();
    }

    pub fn join_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
        not_available!();
    }

    pub fn join_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        not_available!();
    }

    pub fn leave_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
        not_available!();
    }

    pub fn leave_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
        not_available!();
    }

    pub fn set_ttl(&self, _: u32) -> io::Result<()> {
        not_available!();
    }

    pub fn ttl(&self) -> io::Result<u32> {
        not_available!();
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        not_available!();
    }

    pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        not_available!();
    }

    pub fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
        not_available!();
    }

    pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
        not_available!();
    }

    pub fn send(&self, _: &[u8]) -> io::Result<usize> {
        not_available!();
    }

    pub fn connect(&self, _: io::Result<&SocketAddr>) -> io::Result<()> {
        not_available!();
    }
}

impl FromInner<Socket> for UdpSocket {
    fn from_inner(socket: Socket) -> UdpSocket {
        UdpSocket { inner: socket }
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP sockets not supported on Fortanixvme.")
    }
}
