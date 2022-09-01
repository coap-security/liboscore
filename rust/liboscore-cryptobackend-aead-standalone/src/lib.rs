#![no_std]
#![feature(core_intrinsics)]
#![feature(lang_items)]

use core::panic::PanicInfo;

pub use liboscore_cryptobackend_aead::*;
pub use liboscore_cryptobackend_hkdf::*;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    core::intrinsics::abort()
}

#[lang = "eh_personality"]
extern fn eh_personality() {}
