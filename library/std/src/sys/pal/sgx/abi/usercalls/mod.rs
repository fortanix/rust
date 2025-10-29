use crate::cmp;
use crate::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Result as IoResult};
use crate::random::{DefaultRandomSource, Random};
use crate::sync::OnceLock;
use crate::time::{Duration, Instant};
use crate::ops::Add;
use insecure_time::{Freq, Tsc, TscBuilder, LearningFreqTscBuilder, NativeTime, NoRdtscTscBuilder};

pub(crate) mod alloc;
#[macro_use]
pub(crate) mod raw;
#[cfg(test)]
mod tests;

use self::raw::*;
use self::alloc::UserRef;

/// Usercall `read`. See the ABI documentation for more information.
///
/// This will do a single `read` usercall and scatter the read data among
/// `bufs`. To read to a single buffer, just pass a slice of length one.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn read(fd: Fd, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
    unsafe {
        let total_len = bufs.iter().fold(0usize, |sum, buf| sum.saturating_add(buf.len()));
        let mut userbuf = alloc::User::<[u8]>::uninitialized(total_len);
        let ret_len = raw::read(fd, userbuf.as_mut_ptr(), userbuf.len()).from_sgx_result()?;
        let userbuf = &userbuf[..ret_len];
        let mut index = 0;
        for buf in bufs {
            let end = cmp::min(index + buf.len(), userbuf.len());
            if let Some(buflen) = end.checked_sub(index) {
                userbuf[index..end].copy_to_enclave(&mut buf[..buflen]);
                index += buf.len();
            } else {
                break;
            }
        }
        Ok(userbuf.len())
    }
}

/// Usercall `read_alloc`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn read_alloc(fd: Fd) -> IoResult<Vec<u8>> {
    unsafe {
        let userbuf = ByteBuffer { data: crate::ptr::null_mut(), len: 0 };
        let mut userbuf = alloc::User::new_from_enclave(&userbuf);
        raw::read_alloc(fd, userbuf.as_raw_mut_ptr()).from_sgx_result()?;
        Ok(userbuf.copy_user_buffer())
    }
}

/// Usercall `write`. See the ABI documentation for more information.
///
/// This will do a single `write` usercall and gather the written data from
/// `bufs`. To write from a single buffer, just pass a slice of length one.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn write(fd: Fd, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
    unsafe {
        let total_len = bufs.iter().fold(0usize, |sum, buf| sum.saturating_add(buf.len()));
        let mut userbuf = alloc::User::<[u8]>::uninitialized(total_len);
        let mut index = 0;
        for buf in bufs {
            let end = cmp::min(index + buf.len(), userbuf.len());
            if let Some(buflen) = end.checked_sub(index) {
                userbuf[index..end].copy_from_enclave(&buf[..buflen]);
                index += buf.len();
            } else {
                break;
            }
        }
        raw::write(fd, userbuf.as_ptr(), userbuf.len()).from_sgx_result()
    }
}

/// Usercall `flush`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn flush(fd: Fd) -> IoResult<()> {
    unsafe { raw::flush(fd).from_sgx_result() }
}

/// Usercall `close`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn close(fd: Fd) {
    unsafe { raw::close(fd) }
}

fn string_from_bytebuffer(buf: &alloc::UserRef<ByteBuffer>, usercall: &str, arg: &str) -> String {
    String::from_utf8(buf.copy_user_buffer())
        .unwrap_or_else(|_| rtabort!("Usercall {usercall}: expected {arg} to be valid UTF-8"))
}

/// Usercall `bind_stream`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn bind_stream(addr: &str) -> IoResult<(Fd, String)> {
    unsafe {
        let addr_user = alloc::User::new_from_enclave(addr.as_bytes());
        let mut local = alloc::User::<ByteBuffer>::uninitialized();
        let fd = raw::bind_stream(addr_user.as_ptr(), addr_user.len(), local.as_raw_mut_ptr())
            .from_sgx_result()?;
        let local = string_from_bytebuffer(&local, "bind_stream", "local_addr");
        Ok((fd, local))
    }
}

/// Usercall `accept_stream`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn accept_stream(fd: Fd) -> IoResult<(Fd, String, String)> {
    unsafe {
        let mut bufs = alloc::User::<[ByteBuffer; 2]>::uninitialized();
        let mut buf_it = alloc::UserRef::iter_mut(&mut *bufs); // FIXME: can this be done
        // without forcing coercion?
        let (local, peer) = (buf_it.next().unwrap(), buf_it.next().unwrap());
        let fd = raw::accept_stream(fd, local.as_raw_mut_ptr(), peer.as_raw_mut_ptr())
            .from_sgx_result()?;
        let local = string_from_bytebuffer(&local, "accept_stream", "local_addr");
        let peer = string_from_bytebuffer(&peer, "accept_stream", "peer_addr");
        Ok((fd, local, peer))
    }
}

/// Usercall `connect_stream`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn connect_stream(addr: &str) -> IoResult<(Fd, String, String)> {
    unsafe {
        let addr_user = alloc::User::new_from_enclave(addr.as_bytes());
        let mut bufs = alloc::User::<[ByteBuffer; 2]>::uninitialized();
        let mut buf_it = alloc::UserRef::iter_mut(&mut *bufs); // FIXME: can this be done
        // without forcing coercion?
        let (local, peer) = (buf_it.next().unwrap(), buf_it.next().unwrap());
        let fd = raw::connect_stream(
            addr_user.as_ptr(),
            addr_user.len(),
            local.as_raw_mut_ptr(),
            peer.as_raw_mut_ptr(),
        )
        .from_sgx_result()?;
        let local = string_from_bytebuffer(&local, "connect_stream", "local_addr");
        let peer = string_from_bytebuffer(&peer, "connect_stream", "peer_addr");
        Ok((fd, local, peer))
    }
}

/// Usercall `launch_thread`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub unsafe fn launch_thread() -> IoResult<()> {
    // SAFETY: The caller must uphold the safety contract for `launch_thread`.
    unsafe { raw::launch_thread().from_sgx_result() }
}

/// Usercall `exit`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn exit(panic: bool) -> ! {
    unsafe { raw::exit(panic) }
}

/// Usercall `wait`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn wait(event_mask: u64, mut timeout: u64) -> IoResult<u64> {
    if timeout != WAIT_NO && timeout != WAIT_INDEFINITE {
        // We don't want people to rely on accuracy of timeouts to make
        // security decisions in an SGX enclave. That's why we add a random
        // amount not exceeding +/- 10% to the timeout value to discourage
        // people from relying on accuracy of timeouts while providing a way
        // to make things work in other cases. Note that in the SGX threat
        // model the enclave runner which is serving the wait usercall is not
        // trusted to ensure accurate timeouts.
        if let Ok(timeout_signed) = i64::try_from(timeout) {
            let tenth = timeout_signed / 10;
            let deviation = i64::random(&mut DefaultRandomSource).checked_rem(tenth).unwrap_or(0);
            timeout = timeout_signed.saturating_add(deviation) as _;
        }
    }
    unsafe { raw::wait(event_mask, timeout).from_sgx_result() }
}

/// Makes an effort to wait for a non-spurious event at least as long as
/// `duration`.
///
/// Note that in general there is no guarantee about accuracy of time and
/// timeouts in SGX model. The enclave runner serving usercalls may lie about
/// current time and/or ignore timeout values.
///
/// Once the event is observed, `should_wake_up` will be used to determine
/// whether or not the event was spurious.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn wait_timeout<F>(event_mask: u64, duration: Duration, should_wake_up: F)
where
    F: Fn() -> bool,
{
    // Calls the wait usercall and checks the result. Returns true if event was
    // returned, and false if WouldBlock/TimedOut was returned.
    // If duration is None, it will use WAIT_NO.
    fn wait_checked(event_mask: u64, duration: Option<Duration>) -> bool {
        let timeout = duration.map_or(raw::WAIT_NO, |duration| {
            cmp::min((u64::MAX - 1) as u128, duration.as_nanos()) as u64
        });
        match wait(event_mask, timeout) {
            Ok(eventset) => {
                if event_mask == 0 {
                    rtabort!("expected wait() to return Err, found Ok.");
                }
                rtassert!(eventset != 0 && eventset & !event_mask == 0);
                true
            }
            Err(e) => {
                rtassert!(e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock);
                false
            }
        }
    }

    match wait_checked(event_mask, Some(duration)) {
        false => return,                    // timed out
        true if should_wake_up() => return, // woken up
        true => {}                          // spurious event
    }

    // Drain all cached events.
    // Note that `event_mask != 0` is implied if we get here.
    loop {
        match wait_checked(event_mask, None) {
            false => break,                     // no more cached events
            true if should_wake_up() => return, // woken up
            true => {}                          // spurious event
        }
    }

    // Continue waiting, but take note of time spent waiting so we don't wait
    // forever. We intentionally don't call `Instant::now()` before this point
    // to avoid the cost of the `insecure_time` usercall in case there are no
    // spurious wakeups.

    let start = Instant::now();
    let mut remaining = duration;
    loop {
        match wait_checked(event_mask, Some(remaining)) {
            false => return,                    // timed out
            true if should_wake_up() => return, // woken up
            true => {}                          // spurious event
        }
        remaining = match duration.checked_sub(start.elapsed()) {
            Some(remaining) => remaining,
            None => break,
        }
    }
}

/// Usercall `send`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn send(event_set: u64, tcs: Option<Tcs>) -> IoResult<()> {
    unsafe { raw::send(event_set, tcs).from_sgx_result() }
}

#[derive(Copy, Clone, PartialOrd, PartialEq)]
struct SgxTime(u64);

impl SgxTime {
    const NANOS_PER_SEC: u32 = 1_000_000_000;

    pub fn as_duration(&self) -> Duration {
        Duration::new(self.0 / Self::NANOS_PER_SEC as u64, (self.0 % Self::NANOS_PER_SEC as u64) as _)
    }
}

impl Add<Duration> for SgxTime {
    type Output = SgxTime;

    fn add(self, other: Duration) -> Self::Output {
        let t = self.0 + other.as_secs() * Self::NANOS_PER_SEC as u64 + other.subsec_nanos() as u64;
        SgxTime(t)
    }
}

impl NativeTime for SgxTime {
    fn minimum() -> SgxTime {
        SgxTime(0)
    }

    fn abs_diff(&self, other: &Self) -> Duration {
        Duration::from_nanos(self.0.abs_diff(other.0))
    }

    fn now() -> Self {
        let (t, _info) = unsafe { raw::insecure_time() };
        SgxTime(t)
    }
}

/// Usercall `insecure_time`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn insecure_time() -> Duration {
    static TSC: OnceLock<Tsc<SgxTime>> = OnceLock::new();

    let tsc = TSC.get_or_init(|| {
        let (_t, info) = unsafe { raw::insecure_time() };
        let freq = if !info.is_null() {
            let info = unsafe { UserRef::<InsecureTimeInfo>::from_ptr(info).to_enclave() };
            if info.frequency != 0 {
                Some(Freq::from_u64(info.frequency))
            } else {
                // Enclave runner passed in info, but the host didn't report frequency. In
                // the current implementation of the runner, that can't happen, but we may need
                // something like that in the future when we pass in additional info. Just being
                // very defensive here.
                None
            }
        } else {
            // Old enclave runner that doesn't pass in information
            None
        };

        if let Some(freq) = freq {
            LearningFreqTscBuilder::new()
                .set_initial_frequency(freq)
                .set_frequency_learning_period(Duration::from_secs(120))
                .set_max_acceptable_drift(Duration::from_millis(1))
                .set_max_sync_interval(Duration::from_secs(60))
                .set_monotonic_time()
                .build()
        } else {
            NoRdtscTscBuilder::new()
                .set_monotonic_time()
                .build()
        }
    });
    tsc.now().as_duration()
}

/// Usercall `alloc`. See the ABI documentation for more information.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn alloc(size: usize, alignment: usize) -> IoResult<*mut u8> {
    unsafe { raw::alloc(size, alignment).from_sgx_result() }
}

#[unstable(feature = "sgx_platform", issue = "56975")]
#[doc(inline)]
pub use self::raw::free;

fn check_os_error(err: Result) -> i32 {
    // FIXME: not sure how to make sure all variants of Error are covered
    if err == Error::NotFound as _
        || err == Error::PermissionDenied as _
        || err == Error::ConnectionRefused as _
        || err == Error::ConnectionReset as _
        || err == Error::ConnectionAborted as _
        || err == Error::NotConnected as _
        || err == Error::AddrInUse as _
        || err == Error::AddrNotAvailable as _
        || err == Error::BrokenPipe as _
        || err == Error::AlreadyExists as _
        || err == Error::WouldBlock as _
        || err == Error::InvalidInput as _
        || err == Error::InvalidData as _
        || err == Error::TimedOut as _
        || err == Error::WriteZero as _
        || err == Error::Interrupted as _
        || err == Error::Other as _
        || err == Error::UnexpectedEof as _
        || ((Error::UserRangeStart as _)..=(Error::UserRangeEnd as _)).contains(&err)
    {
        err
    } else {
        rtabort!("Usercall: returned invalid error value {err}")
    }
}

/// Translate the raw result of an SGX usercall.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub trait FromSgxResult {
    /// Return type
    type Return;

    /// Translate the raw result of an SGX usercall.
    fn from_sgx_result(self) -> IoResult<Self::Return>;
}

#[unstable(feature = "sgx_platform", issue = "56975")]
impl<T> FromSgxResult for (Result, T) {
    type Return = T;

    fn from_sgx_result(self) -> IoResult<Self::Return> {
        if self.0 == RESULT_SUCCESS {
            Ok(self.1)
        } else {
            Err(IoError::from_raw_os_error(check_os_error(self.0)))
        }
    }
}

#[unstable(feature = "sgx_platform", issue = "56975")]
impl FromSgxResult for Result {
    type Return = ();

    fn from_sgx_result(self) -> IoResult<Self::Return> {
        if self == RESULT_SUCCESS {
            Ok(())
        } else {
            Err(IoError::from_raw_os_error(check_os_error(self)))
        }
    }
}
