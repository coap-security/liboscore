// Not using them directly, but they have to be linked in for the C functions to be available.
extern crate liboscore_cryptobackend;

include!(concat!(env!("OUT_DIR"), "/testmain-list.rs"));

fn main() -> Result<(), &'static str> {
    let mut first_error = Ok(());
    for (name, tmf) in TESTMAINS {
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
    }
    first_error
}
