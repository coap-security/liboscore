//! Implementation of the few libc functions libOSCORE needs, providing backends for
//! oscore_native/platform.h
//!
//! This only implements functions as used; it seems that the string functions are all well handled
//! by the compilers internally anyway (which makes sense -- after all, in Rust they are part of
//! core, only in C it was chosen not to make them part of the freestanding set).

#[no_mangle]
extern "C" fn assert(expression: bool) {
    debug_assert!(expression, "Assert from C failed");
}

#[no_mangle]
extern "C" fn abort() {
    panic!("Abort triggered from C");
}
