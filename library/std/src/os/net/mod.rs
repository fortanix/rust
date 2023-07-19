//! OS-specific networking functionality.

// See cfg macros in `library/std/src/os/mod.rs` for why these platforms must
// be special-cased during rustdoc generation.
#[cfg(not(all(
    doc,
    any(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        all(target_vendor = "fortanix", target_env = "sgx")
    )
)))]
#[cfg(all(any(target_os = "linux", target_os = "android", not(target_env = "fortanixvme")), doc))]
pub(super) mod linux_ext;
