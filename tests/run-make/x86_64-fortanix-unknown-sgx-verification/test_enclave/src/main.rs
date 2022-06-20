#![feature(sgx_platform)]
use std::time::Duration;

use std::os::fortanix_sgx::mem::{
    image_base,
    is_enclave_range
};
use std::os::fortanix_sgx::usercalls::raw::{ByteBuffer, Fd, FifoDescriptor, Result, Return, Usercall};

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

#[no_mangle]
#[inline(never)]
pub fn raw_accept_stream(fd: Fd, local_addr: *mut ByteBuffer, peer_addr: *mut ByteBuffer) -> (Result, Fd) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::accept_stream(fd, local_addr, peer_addr) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_alloc(size: usize, alignment: usize) -> (Result, *mut u8) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::alloc(size, alignment) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_async_queues(usercall_queue: *mut FifoDescriptor<Usercall>, return_queue: *mut FifoDescriptor<Return>) -> Result {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::async_queues(usercall_queue, return_queue) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_bind_stream(addr: *const u8, len: usize, local_addr: *mut ByteBuffer) -> (Result, Fd) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::bind_stream(addr, len, local_addr) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_close(fd: Fd) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::close(fd) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_connect_stream(addr: *const u8, len: usize, local_addr: *mut ByteBuffer, peer_addr: *mut ByteBuffer) -> (Result, Fd) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::connect_stream(addr, len, local_addr, peer_addr) }
}

fn main() {
    println!("image base: {}", get_image_base());
    println!("is_enclave_range: {}", verify_is_enclave_range(0x0 as _, 10));
    println!("time: {}", insecure_time().as_nanos());
    println!("raw_read: {:?}", raw_read(0, std::ptr::null_mut(), 0));
    println!("raw_read_alloc: {:?}", raw_read_alloc(0, std::ptr::null_mut()));
    println!("raw_accept_stream: {:?}", raw_accept_stream(0, std::ptr::null_mut(), std::ptr::null_mut()));
    println!("raw_alloc: {:?}", raw_alloc(0, 0));
    println!("raw_async_queues: {:?}", raw_async_queues(std::ptr::null_mut(), std::ptr::null_mut()));
    println!("raw_bind_stream: {:?}", raw_bind_stream(std::ptr::null(), 0, std::ptr::null_mut()));
    println!("raw_close: {:?}", raw_close(0));
    println!("raw_connect_stream: {:?}", raw_connect_stream(std::ptr::null(), 0, std::ptr::null_mut(), std::ptr::null_mut()));


            //accept_stream, alloc, async_queues, bind_stream, close, connect_stream, exit, flush,
            //free, launch_thread, send, wait, write,
}
