#![feature(sgx_platform)]

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

fn main() {
    println!("Hello, world!");
    println!("image base: {}", get_image_base());
    println!("is_enclave_range: {}", verify_is_enclave_range(0x0 as _, 10));
}

#[test]
fn test_is_enclave_range() {
    assert!(!verify_is_enclave_range(0x65408047ffc135fc as u64 as *const u8, 0x8a813ff9002e0000))
}
