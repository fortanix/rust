#![feature(sgx_platform)]
use std::time::Duration;

use std::os::fortanix_sgx::mem::{
    image_base,
    is_enclave_range
};
use std::os::fortanix_sgx::usercalls::raw::{ByteBuffer, Fd, Result};

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
pub fn insecure_time() -> Duration {
    std::os::fortanix_sgx::usercalls::insecure_time()
}

#[no_mangle]
#[inline(never)]
pub fn raw_read(fd: Fd, buf: *mut u8, len: usize) -> (Result, usize) {
    unsafe { std::os::fortanix_sgx::usercalls::raw::read(fd, buf, len) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_read_alloc(fd: Fd, buf: *mut ByteBuffer) -> Result {
    unsafe { std::os::fortanix_sgx::usercalls::raw::read_alloc(fd, buf) }
}

fn main() {
    println!("image base: {}", get_image_base());
    println!("is_enclave_range: {}", verify_is_enclave_range(0x0 as _, 10));
    println!("time: {}", insecure_time().as_nanos());
    println!("raw_read: {:?}", raw_read(0, std::ptr::null_mut(), 0));
    println!("raw_read_alloc: {:?}", raw_read_alloc(0, std::ptr::null_mut()));


            //accept_stream, alloc, async_queues, bind_stream, close, connect_stream, exit, flush,
            //free, insecure_time, launch_thread, read_alloc, send, wait, write,
}
