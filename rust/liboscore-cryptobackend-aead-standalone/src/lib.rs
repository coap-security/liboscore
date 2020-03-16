#![no_std]
#![feature(core_intrinsics)]
#![feature(lang_items)]

use core::panic::PanicInfo;

pub use liboscore_cryptobackend_aead::*;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { core::intrinsics::abort() }
}

#[lang = "eh_personality"]
extern fn eh_personality() {}
