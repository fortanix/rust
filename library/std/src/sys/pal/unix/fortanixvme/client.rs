use enclave_runner_client::{Client, Error, IoError};

pub use enclave_runner_client::{Addr, VsockAddr, ConnectionInfo};

use crate::ops::{Deref, DerefMut};
use crate::io::{self};
use crate::fmt::{self, Display, Formatter};

#[derive(Debug)]
struct ErrorWrapper(Error);

// Compiler bug in nightly-2021-09-08-x86_64-unknown-linux-gnu requires both annotations
#[allow(ineffective_unstable_trait_impl)]
#[unstable(feature = "fortanixvme", issue = "none")]
impl crate::error::Error for ErrorWrapper {}

impl Display for ErrorWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        self.0.fmt(f)
    }
}

impl From<Error> for ErrorWrapper {
    fn from(e: Error) -> ErrorWrapper {
        ErrorWrapper(e)
    }
}

// Compiler bug in nightly-2021-09-08-x86_64-unknown-linux-gnu requires both annotations
#[allow(ineffective_unstable_trait_impl)]
#[unstable(feature = "fortanixvme", issue = "none")]
impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            Error::InvalidInput => {
                io::Error::new(io::ErrorKind::InvalidInput, ErrorWrapper::from(err))
            }
            Error::SystemError(errno) => io::Error::from_raw_os_error(errno),
            Error::IoError(ref error) => {
                io::Error::new(io::ErrorKind::from(error), ErrorWrapper::from(err))
            }
            Error::SerializationError => {
                //TODO
                io::Error::new(io::ErrorKind::Other, ErrorWrapper::from(err))
            }
            Error::DeserializationError => {
                //TODO
                io::Error::new(io::ErrorKind::Other, ErrorWrapper::from(err))
            }
            Error::MissingFd => {
                //TODO
                io::Error::new(io::ErrorKind::Other, ErrorWrapper::from(err))
            }
            Error::Other(ref _reason) => {
                io::Error::new(io::ErrorKind::Other, ErrorWrapper::from(err))
            }
        }
    }
}

#[unstable(feature = "fortanixvme", issue = "none")]
impl From<&IoError> for io::ErrorKind {
    fn from(kind: &IoError) -> io::ErrorKind {
        match kind {
            IoError::NotFound => io::ErrorKind::NotFound,
            IoError::PermissionDenied => io::ErrorKind::PermissionDenied,
            IoError::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            IoError::ConnectionReset => io::ErrorKind::ConnectionReset,
            IoError::HostUnreachable => io::ErrorKind::HostUnreachable,
            IoError::NetworkUnreachable => io::ErrorKind::NetworkUnreachable,
            IoError::ConnectionAborted => io::ErrorKind::ConnectionAborted,
            IoError::NotConnected => io::ErrorKind::NotConnected,
            IoError::AddrInUse => io::ErrorKind::AddrInUse,
            IoError::AddrNotAvailable => io::ErrorKind::AddrNotAvailable,
            IoError::NetworkDown => io::ErrorKind::NetworkDown,
            IoError::BrokenPipe => io::ErrorKind::BrokenPipe,
            IoError::AlreadyExists => io::ErrorKind::AlreadyExists,
            IoError::WouldBlock => io::ErrorKind::WouldBlock,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::NotADirectory => io::ErrorKind::NotADirectory,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::IsADirectory => io::ErrorKind::IsADirectory,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::DirectoryNotEmpty => io::ErrorKind::DirectoryNotEmpty,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::ReadOnlyFilesystem => io::ErrorKind::ReadOnlyFilesystem,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::FilesystemLoop => io::ErrorKind::FilesystemLoop,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::StaleNetworkFileHandle => {
                io::ErrorKind::StaleNetworkFileHandle
            }
            IoError::InvalidInput => io::ErrorKind::InvalidInput,
            IoError::InvalidData => io::ErrorKind::InvalidData,
            IoError::TimedOut => io::ErrorKind::TimedOut,
            IoError::WriteZero => io::ErrorKind::WriteZero,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::StorageFull => io::ErrorKind::StorageFull,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::NotSeekable => io::ErrorKind::NotSeekable,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::FilesystemQuotaExceeded => io::ErrorKind::QuotaExceeded,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::FileTooLarge => io::ErrorKind::FileTooLarge,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::ResourceBusy => io::ErrorKind::ResourceBusy,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::ExecutableFileBusy => io::ErrorKind::ExecutableFileBusy,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::Deadlock => io::ErrorKind::Deadlock,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::CrossesDevices => io::ErrorKind::CrossesDevices,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::TooManyLinks => io::ErrorKind::TooManyLinks,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            //fortanix_vme_abi::ErrorKind::FilenameTooLong => io::ErrorKind::FilenameTooLong,
            //#[unstable(feature = "io_error_more", issue = "86442")]
            IoError::ArgumentListTooLong => io::ErrorKind::ArgumentListTooLong,
            IoError::Interrupted => io::ErrorKind::Interrupted,
            IoError::Unsupported => io::ErrorKind::Unsupported,
            IoError::UnexpectedEof => io::ErrorKind::UnexpectedEof,
            IoError::OutOfMemory => io::ErrorKind::OutOfMemory,
            IoError::Other => io::ErrorKind::Other,
            //#[unstable(feature = "io_error_uncategorized", issue = "none")]
            IoError::Uncategorized => io::ErrorKind::Uncategorized,
        }
    }
}

#[unstable(feature = "fortanixvme", issue = "none")]
impl From<IoError> for io::ErrorKind {
    fn from(kind: IoError) -> io::ErrorKind {
        io::ErrorKind::from(&kind)
    }
}

pub struct RunnerClient {
    inner: Client,
}

impl RunnerClient {
    pub fn new() -> Result<Self, Error> {
        Ok(RunnerClient { inner: Client::new(None)? })
    }

    pub fn args() -> Result<Vec<String>, Error> {
        Client::args(None)
    }

    pub fn exit(code: i32) -> ! {
        Client::exit(None, code)
    }

    pub fn local_vsock_addr(fd: i32) -> Result<VsockAddr, Error> {
        Client::local_vsock_addr(fd)
    }

    pub fn close_connection(port: u32) -> Result<(), Error> {
        Client::close_connection(None, port)
    }
}

impl Deref for RunnerClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.inner
    }
}

impl DerefMut for RunnerClient {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.inner
    }
}