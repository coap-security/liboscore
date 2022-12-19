// Not using them directly, but they have to be linked in for the C functions to be available.
extern crate liboscore_cryptobackend;
extern crate liboscore_msgbackend;

mod raw;
mod impl_message;
mod unprotect_demo;

include!(concat!(env!("OUT_DIR"), "/testmain-list.rs"));

fn run_c_test(name: &'static str, tmf: unsafe extern "C" fn(i32) -> i32) -> Result<(), &'static str> {
    let mut first_error = Ok(());

    println!("Running test case {} without introducing errors...", name);
    let result = unsafe { tmf(0) };
    println!("Test ran, result was {}", result);
    if result != 0 && first_error.is_ok() {
        first_error = Err(name);
    }
    println!("Running test case {} and introducing errors...", name);
    let result = unsafe { tmf(1) };
    println!("Test ran, result was {}", result);
    if result == 0 && first_error.is_ok() {
        first_error = Err(name);
    }

    first_error
}

fn main() -> Result<(), &'static str> {
    let mut first_error = Ok(());
    for (name, test_main_function) in TESTMAINS {
        let result = run_c_test(name, test_main_function);
        if first_error.is_ok() {
            first_error = result;
        }
    }

    let result = unprotect_demo::run();
    if first_error.is_ok() {
        first_error = result;
    }

    first_error
}
