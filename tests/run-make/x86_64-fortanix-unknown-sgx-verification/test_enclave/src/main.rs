#![feature(sgx_platform)]
use std::time::Duration;

use std::os::fortanix_sgx::mem::{
    image_base,
    is_enclave_range
};

#[no_mangle]
#[inline(never)]
pub fn get_image_base() -> u64 {
    image_base()
}

#[no_mangle]
#[inline(never)]
pub fn verify_is_enclave_range(p: *const u8, len: usize) -> bool {
    is_enclave_range(p, len)
}

#[no_mangle]
#[inline(never)]
pub fn wrap_insecure_time() -> Duration {
    std::os::fortanix_sgx::usercalls::insecure_time()
}

fn main() {
    println!("Hello, world!");
    println!("image base: {}", get_image_base());
    println!("is_enclave_range: {}", verify_is_enclave_range(0x0 as _, 10));
    println!("time: {}", wrap_insecure_time().as_nanos());
}

#[test]
fn test_is_enclave_range() {
    assert!(!verify_is_enclave_range(0x65408047ffc135fc as u64 as *const u8, 0x8a813ff9002e0000))
}
