#![feature(sgx_platform)]
use std::time::Duration;

use std::os::fortanix_sgx::mem::{
    image_base,
    is_enclave_range
};
use std::os::fortanix_sgx::usercalls::raw::{ByteBuffer, Fd, FifoDescriptor, Result, Return, Tcs, Usercall};
use std::io::Result as IoResult;

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
pub fn read_alloc(fd: Fd) -> std::io::Result<Vec<u8>> {
    std::os::fortanix_sgx::usercalls::read_alloc(fd)
}

#[no_mangle]
#[inline(never)]
pub fn raw_accept_stream(fd: Fd, local_addr: *mut ByteBuffer, peer_addr: *mut ByteBuffer) -> (Result, Fd) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::accept_stream(fd, local_addr, peer_addr) }
}

#[no_mangle]
#[inline(never)]
pub fn accept_stream() -> IoResult<(Fd, String, String)> {
    let fd = 0;
    std::os::fortanix_sgx::usercalls::accept_stream(fd)
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
pub fn bind_stream(addr: &str) -> IoResult<(Fd, String)> {
    std::os::fortanix_sgx::usercalls::bind_stream(addr)
}

#[no_mangle]
#[inline(never)]
pub fn raw_close(fd: Fd) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::close(fd) }
}

#[no_mangle]
#[inline(never)]
pub fn close(fd: Fd) {
    std::os::fortanix_sgx::usercalls::close(fd)
}

#[no_mangle]
#[inline(never)]
pub fn raw_connect_stream(addr: *const u8, len: usize, local_addr: *mut ByteBuffer, peer_addr: *mut ByteBuffer) -> (Result, Fd) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::connect_stream(addr, len, local_addr, peer_addr) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_exit(v: bool) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::exit(v) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_flush(fd: Fd) -> Result {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::flush(fd) }
}

#[no_mangle]
#[inline(never)]
pub fn flush(fd: Fd) -> IoResult<()> {
    std::os::fortanix_sgx::usercalls::flush(fd)
}

#[no_mangle]
#[inline(never)]
pub fn raw_free(ptr: *mut u8, size: usize, alignment: usize) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::free(ptr, size, alignment) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_launch_thread() -> Result {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::launch_thread() }
}

#[no_mangle]
#[inline(never)]
pub fn raw_send(event_set: u64, target: Option<Tcs>) -> Result {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::send(event_set, target) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_wait(event: u64, timeout: u64) -> (Result, u64) {
    unsafe{ std::os::fortanix_sgx::usercalls::raw::wait(event, timeout) }
}

#[no_mangle]
#[inline(never)]
pub fn raw_write(fd: Fd, buf: *mut u8, len: usize) -> (Result, usize) {
    unsafe { std::os::fortanix_sgx::usercalls::raw::write(fd, buf, len) }
}

fn main() {
    println!("image base: {}", get_image_base());
    println!("is_enclave_range: {}", verify_is_enclave_range(0x0 as _, 10));
    println!("time: {}", insecure_time().as_nanos());
    println!("raw_read: {:?}", raw_read(0, std::ptr::null_mut(), 0));
    println!("raw_read_alloc: {:?}", raw_read_alloc(0, std::ptr::null_mut()));
    println!("read_alloc: {:?}", read_alloc(0));
    println!("raw_accept_stream: {:?}", raw_accept_stream(0, std::ptr::null_mut(), std::ptr::null_mut()));
    println!("accept_stream: {:?}", accept_stream());
    println!("raw_alloc: {:?}", raw_alloc(0, 0));
    println!("raw_async_queues: {:?}", raw_async_queues(std::ptr::null_mut(), std::ptr::null_mut()));
    println!("raw_bind_stream: {:?}", raw_bind_stream(std::ptr::null(), 0, std::ptr::null_mut()));
    println!("bind_stream: {:?}", bind_stream(""));
    println!("raw_close: {:?}", raw_close(0));
    println!("close: {:?}", close(0));
    println!("raw_connect_stream: {:?}", raw_connect_stream(std::ptr::null(), 0, std::ptr::null_mut(), std::ptr::null_mut()));
    println!("raw_flush: {:?}", raw_flush(0));
    println!("flush: {:?}", flush(0));
    println!("raw_free: {:?}", raw_free(std::ptr::null_mut(), 0, 0));
    println!("raw_launch_thread: {:?}", raw_launch_thread());
    println!("raw_send: {:?}", raw_send(0, None));
    println!("raw_wait: {:?}", raw_wait(0, 0));
    println!("raw_write: {:?}", raw_write(0, std::ptr::null_mut(), 0));
    println!("raw_exit: {:?}", raw_exit(true));


            //accept_stream, alloc, async_queues, bind_stream, close, connect_stream, exit, flush,
            //free, launch_thread, send, wait, write,
}
