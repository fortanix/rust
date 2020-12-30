use crate::ptr;

// Do not remove inline: will result in relocation failure
#[inline(always)]
pub(crate) unsafe fn rel_ptr<T>(offset: u64) -> *const T {
    (image_base() + offset) as *const T
}

// Do not remove inline: will result in relocation failure
#[inline(always)]
pub(crate) unsafe fn rel_ptr_mut<T>(offset: u64) -> *mut T {
    (image_base() + offset) as *mut T
}

extern "C" {
    static ENCLAVE_SIZE: usize;
    static TCS_LIST: u64;
}

// Do not remove inline: will result in relocation failure
// For the same reason we use inline ASM here instead of an extern static to
// locate the base
/// Returns address at which current enclave is loaded.
#[inline(always)]
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn image_base() -> u64 {
    let base: u64;
    unsafe {
        asm!(
            "lea IMAGE_BASE(%rip), {}",
            lateout(reg) base,
            // NOTE(#76738): ATT syntax is used to support LLVM 8 and 9.
            options(att_syntax, nostack, preserves_flags, nomem, pure),
        )
    };
    base
}

/// Returns `true` if the specified memory range is in the enclave.
///
/// `p + len` must not overflow.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn is_enclave_range(p: *const u8, len: usize) -> bool {
    let start = p as u64;
    let end = start + (len as u64);
    start >= image_base() && end <= image_base() + (unsafe { ENCLAVE_SIZE } as u64) // unsafe ok: link-time constant
}

/// Returns `true` if the specified memory range is in userspace.
///
/// `p + len` must not overflow.
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn is_user_range(p: *const u8, len: usize) -> bool {
    let start = p as u64;
    let end = start + (len as u64);
    end <= image_base() || start >= image_base() + (unsafe { ENCLAVE_SIZE } as u64) // unsafe ok: link-time constant
}

#[repr(C, packed)]
#[derive(Default)]
struct TcslsTcsListItem {
    tcs_offset: u64,
    next_offset: u64,
}

/// Returns the location of all TCSes available at compile time in the enclave
#[unstable(feature = "sgx_platform", issue = "56975")]
pub fn tcses() -> Vec<u64> {
    unsafe {
        let mut item: *const TcslsTcsListItem = rel_ptr(TCS_LIST);
        let mut tcses = Vec::new();

        while item != ptr::null() {
            tcses.push((*item).tcs_offset + image_base());
            item = if (*item).next_offset != 0 {
                ((*item).next_offset + image_base()) as _
            } else {
                ptr::null()
            }
        }
        tcses
    }
}
