#![feature(sgx_platform)]

use std::os::fortanix_sgx::mem::image_base;

#[no_mangle]
#[inline(never)]
pub fn get_image_base() -> u64 {
    image_base()
}

fn main() {
    println!("Hello, world!");
    println!("image base: {}", get_image_base());
}
