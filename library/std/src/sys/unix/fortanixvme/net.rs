use core::convert::TryFrom;
use crate::cmp;
use crate::io::{self, ErrorKind, IoSlice, IoSliceMut};
use crate::sys::fd::FileDesc;
use crate::sys_common::{AsInner, FromInner, IntoInner};
use crate::time::Duration;
use crate::fmt;
use crate::mem;
use crate::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use crate::os::fd::raw::AsRawFd;
use crate::os::fd::owned::{AsFd, BorrowedFd};
use crate::os::unix::prelude::{IntoRawFd, FromRawFd, RawFd};
use crate::sys::{cvt, cvt_r};
use fortanix_vme_abi::{self, Client, Error, Response, Request};
use libc::{self, c_int, c_void, size_t, MSG_PEEK, MSG_NOSIGNAL};
use vsock::{Platform, VsockStream};

type wrlen_t = size_t;

    pub(crate) extern crate libc as netc;

    struct Fortanixvme;

    impl Platform for Fortanixvme {
        fn last_os_error() -> vsock::Error {
            vsock::Error::SystemError(super::super::os::errno() as i32)
        }
    }

    #[unstable(feature = "fortanixvme", issue = "none")]
    impl From<Error> for io::Error {
        fn from(error: Error) -> io::Error {
            match error {
                Error::SerializationError(e) => io::Error::new(ErrorKind::InvalidData, format!("Serialization error: {}", e)),
                Error::DeserializationError(e) => io::Error::new(ErrorKind::InvalidData, format!("Deserialization error: {}", e)),
                Error::ConnectFailed => io::Error::new(ErrorKind::InvalidData, "Connection failed".to_string()),
                Error::WriteFailed => io::Error::new(ErrorKind::BrokenPipe, "Write failed".to_string()),
                Error::ReadFailed => io::Error::new(ErrorKind::BrokenPipe, "Read failed".to_string()),
                Error::UnexpectedResponse => io::Error::new(ErrorKind::InvalidData, "Unexpected response from runner".to_string()),
            }
        }
    }

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
            // need to downcast twice because io::Error::into_inner doesn't return the original
            // value if the conversion fails
            Err(e) => {
                e.get_ref().and_then(|e| if let Some(addr) = e.downcast_ref::<NonIpSockAddr>() {
                    Some(addr.host().to_owned())
                } else {
                    None
                }).ok_or(e)
            }
        }
    }

    fn getsockopt<T: Copy>(sock: &Socket, opt: c_int, val: c_int) -> io::Result<T> {
        unsafe {
            let mut slot: T = mem::zeroed();
            let mut len = mem::size_of::<T>() as libc::socklen_t;
            cvt(libc::getsockopt(sock.as_raw(), opt, val, &mut slot as *mut _ as *mut _, &mut len))?;
            assert_eq!(len as usize, mem::size_of::<T>());
            Ok(slot)
        }
    }

    macro_rules! unimpl {
        () => {
            return Err(io::Error::new_const(
                io::ErrorKind::Unsupported,
                &"Unimplemented on Fortanixvme",
            ));
        };
    }

    pub struct Socket(FileDesc);

    impl Socket {
        pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
            let how = match how {
                Shutdown::Write => libc::SHUT_WR,
                Shutdown::Read => libc::SHUT_RD,
                Shutdown::Both => libc::SHUT_RDWR,
            };
            cvt(unsafe { libc::shutdown(self.as_raw_fd(), how) })?;
            Ok(())
        }

        pub fn duplicate(&self) -> io::Result<Socket> {
            self.0.duplicate().map(Socket)
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
            self.0.read_vectored(bufs)
        }

        #[inline]
        pub fn is_read_vectored(&self) -> bool {
            self.0.is_read_vectored()
        }

        pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.recv_with_flags(buf, MSG_PEEK)
        }

        pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            self.0.write_vectored(bufs)
        }

        #[inline]
        pub fn is_write_vectored(&self) -> bool {
            self.0.is_write_vectored()
        }

        pub fn take_error(&self) -> io::Result<Option<io::Error>> {
            let raw: c_int = getsockopt(self, libc::SOL_SOCKET, libc::SO_ERROR)?;
            if raw == 0 { Ok(None) } else { Ok(Some(io::Error::from_raw_os_error(raw as i32))) }
        }

        // This is used by sys_common code to abstract over Windows and Unix.
        pub fn as_raw(&self) -> RawFd {
            self.as_raw_fd()
        }
    }
    
    impl FromInner<FileDesc> for Socket {
        fn from_inner(fd: FileDesc) -> Socket {
            Socket(fd)
        }
    }

    impl IntoInner<FileDesc> for Socket {
        fn into_inner(self) -> FileDesc {
            self.0
        }
    }

    impl AsFd for Socket {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.0.as_fd()
        }
    }

    impl AsRawFd for Socket {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    impl IntoRawFd for Socket {
        fn into_raw_fd(self) -> RawFd {
            self.0.into_raw_fd()
        }
    }

    impl FromRawFd for Socket {
        unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
            Self(FromRawFd::from_raw_fd(raw_fd))
        }
    }

    pub struct TcpStream {
        pub(crate) inner: Socket,
    }

    impl From<VsockStream<Fortanixvme>> for TcpStream {
        fn from(stream: VsockStream<Fortanixvme>) -> TcpStream {
            let socket = unsafe{ Socket::from_raw_fd(stream.into_raw_fd()) };
            TcpStream { inner: socket }
        }
    }

    impl TcpStream {
        pub fn connect(addr: io::Result<&SocketAddr>) -> io::Result<TcpStream> {
            let addr = io_err_to_addr(addr)?;
            let mut runner = Client::<Fortanixvme>::new(fortanix_vme_abi::SERVER_PORT)?;
            let stream = runner.open_proxy_connection(addr)?;
            Ok(stream.into())
        }

        pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
            unimpl!()
        }

        pub fn socket(&self) -> &Socket {
            &self.inner
        }

        pub fn into_socket(self) -> Socket {
            self.inner
        }

        pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            unimpl!()
        }

        pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            unimpl!()
        }

        pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
            unimpl!()
        }

        pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
            unimpl!()
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
            let len = cmp::min(buf.len(), <wrlen_t>::MAX as usize) as wrlen_t;
            let ret = cvt(unsafe {
                libc::send(self.inner.as_raw(), buf.as_ptr() as *const c_void, len, MSG_NOSIGNAL)
            })?;
            Ok(ret as usize)
        }

        pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            self.inner.write_vectored(bufs)
        }

        #[inline]
        pub fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        pub fn peer_addr(&self) -> io::Result<SocketAddr> {
            unimpl!()
        }

        pub fn socket_addr(&self) -> io::Result<SocketAddr> {
            unimpl!()
        }

        pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
            self.inner.shutdown(how)
        }

        pub fn duplicate(&self) -> io::Result<TcpStream> {
            self.inner.duplicate().map(|s| TcpStream { inner: s })
        }

        pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
            unimpl!()
        }

        pub fn linger(&self) -> io::Result<Option<Duration>> {
            unimpl!()
        }

        pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
            unimpl!()
        }

        pub fn nodelay(&self) -> io::Result<bool> {
            unimpl!()
        }

        pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
            unimpl!()
        }

        pub fn ttl(&self) -> io::Result<u32> {
            unimpl!()
        }

        pub fn take_error(&self) -> io::Result<Option<io::Error>> {
            self.inner.take_error()
        }

        pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            unimpl!()
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
            unimpl!()
        }

        pub fn socket(&self) -> &Socket {
            &self.inner
        }

        pub fn into_socket(self) -> Socket {
            self.inner
        }

        pub fn socket_addr(&self) -> io::Result<SocketAddr> {
            unimpl!()
        }

        pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
            unimpl!()
        }

        pub fn duplicate(&self) -> io::Result<TcpListener> {
            unimpl!()
        }

        pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
            unimpl!()
        }

        pub fn ttl(&self) -> io::Result<u32> {
            unimpl!()
        }

        pub fn set_only_v6(&self, only_v6: bool) -> io::Result<()> {
            unimpl!()
        }

        pub fn only_v6(&self) -> io::Result<bool> {
            unimpl!()
        }

        pub fn take_error(&self) -> io::Result<Option<io::Error>> {
            unimpl!()
        }

        pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            unimpl!()
        }
    }

    impl FromInner<Socket> for TcpListener {
        fn from_inner(socket: Socket) -> TcpListener {
            TcpListener { inner: socket }
        }
    }

    impl fmt::Debug for TcpListener {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "No networking support available on L4Re.")
        }
    }
    
    pub struct UdpSocket {
        inner: Socket,
    }

    impl UdpSocket {
        pub fn bind(_: io::Result<&SocketAddr>) -> io::Result<UdpSocket> {
            unimpl!();
        }

        pub fn socket(&self) -> &Socket {
            &self.inner
        }

        pub fn into_socket(self) -> Socket {
            self.inner
        }

        pub fn peer_addr(&self) -> io::Result<SocketAddr> {
            unimpl!();
        }

        pub fn socket_addr(&self) -> io::Result<SocketAddr> {
            unimpl!();
        }

        pub fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            unimpl!();
        }

        pub fn peek_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            unimpl!();
        }

        pub fn send_to(&self, _: &[u8], _: &SocketAddr) -> io::Result<usize> {
            unimpl!();
        }

        pub fn duplicate(&self) -> io::Result<UdpSocket> {
            unimpl!();
        }

        pub fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            unimpl!();
        }

        pub fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            unimpl!();
        }

        pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
            unimpl!();
        }

        pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
            unimpl!();
        }

        pub fn set_broadcast(&self, _: bool) -> io::Result<()> {
            unimpl!();
        }

        pub fn broadcast(&self) -> io::Result<bool> {
            unimpl!();
        }

        pub fn set_multicast_loop_v4(&self, _: bool) -> io::Result<()> {
            unimpl!();
        }

        pub fn multicast_loop_v4(&self) -> io::Result<bool> {
            unimpl!();
        }

        pub fn set_multicast_ttl_v4(&self, _: u32) -> io::Result<()> {
            unimpl!();
        }

        pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
            unimpl!();
        }

        pub fn set_multicast_loop_v6(&self, _: bool) -> io::Result<()> {
            unimpl!();
        }

        pub fn multicast_loop_v6(&self) -> io::Result<bool> {
            unimpl!();
        }

        pub fn join_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
            unimpl!();
        }

        pub fn join_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
            unimpl!();
        }

        pub fn leave_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> io::Result<()> {
            unimpl!();
        }

        pub fn leave_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> io::Result<()> {
            unimpl!();
        }

        pub fn set_ttl(&self, _: u32) -> io::Result<()> {
            unimpl!();
        }

        pub fn ttl(&self) -> io::Result<u32> {
            unimpl!();
        }

        pub fn take_error(&self) -> io::Result<Option<io::Error>> {
            unimpl!();
        }

        pub fn set_nonblocking(&self, _: bool) -> io::Result<()> {
            unimpl!();
        }

        pub fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
            unimpl!();
        }

        pub fn peek(&self, _: &mut [u8]) -> io::Result<usize> {
            unimpl!();
        }

        pub fn send(&self, _: &[u8]) -> io::Result<usize> {
            unimpl!();
        }

        pub fn connect(&self, _: io::Result<&SocketAddr>) -> io::Result<()> {
            unimpl!();
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
