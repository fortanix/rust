pub use super::common::Args;
use crate::ffi::OsString;
use crate::sync::OnceLock;
use crate::sys::fortanixvme::client::Client as FortanixvmeClient;

static ARGS: OnceLock<Vec<OsString>> = OnceLock::new();

/// One-time global initialization.
pub unsafe fn init(_argc: isize, _argv: *const *const u8) {
    enclave_args();
}

/// Returns the command line arguments
pub fn args() -> Args {
    let args = enclave_args().to_owned();
    Args::new(args)
}

fn enclave_args() -> &'static Vec<OsString> {
    ARGS.get_or_init(|| {
        FortanixvmeClient::args()
            .expect("Failed to retrieve enclave arguments from runner")
            .iter()
            .map(|arg| OsString::from(arg))
            .collect()
    })
}
