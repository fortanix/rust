use crate::{alloc::{self, GlobalAlloc, System}, cell::Cell, ptr};
use snmalloc_edp::*;
use core::sync::atomic::{AtomicBool, Ordering};

#[stable(feature = "alloc_system_type", since = "1.28.0")]
unsafe impl GlobalAlloc for System {
    #[inline]
    unsafe fn alloc(&self, layout: alloc::Layout) -> *mut u8 {
        static INIT: AtomicBool = AtomicBool::new(false);
        if !INIT.swap(true, Ordering::Relaxed) {
            unsafe { sn_global_init(); }
        }
        unsafe { sn_rust_alloc(layout.align(), layout.size()) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: alloc::Layout) -> *mut u8 {
        // SAFETY: the caller must uphold the safety contract for `malloc`
        unsafe { sn_rust_alloc_zeroed(layout.align(), layout.size()) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: alloc::Layout) {
        // SAFETY: the caller must uphold the safety contract for `malloc`
        unsafe { sn_rust_dealloc(ptr, layout.align(), layout.size()) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: alloc::Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller must uphold the safety contract for `malloc`
        unsafe { sn_rust_realloc(ptr, layout.align(), layout.size(), new_size) }
    }
}

// The following functions are needed by libunwind. These symbols are named
// in pre-link args for the target specification, so keep that in sync.
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn __rust_c_alloc(size: usize, align: usize) -> *mut u8 {
    unsafe { crate::alloc::alloc(crate::alloc::Layout::from_size_align_unchecked(size, align)) }
}

#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn __rust_c_dealloc(ptr: *mut u8, size: usize, align: usize) {
    unsafe { crate::alloc::dealloc(ptr, crate::alloc::Layout::from_size_align_unchecked(size, align)) }
}

thread_local! {
    pub static THREAD_ALLOC: Cell<*mut Alloc> = const { Cell::new(ptr::null_mut()) };
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn __rust_get_thread_allocator() -> *mut Alloc {
    THREAD_ALLOC.get()
}
