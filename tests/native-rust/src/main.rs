// Not using them directly, but they have to be linked in for the C functions to be available.
extern crate liboscore_cryptobackend;

extern "C" {
    fn testmain(introduce_error: i32) -> i32;
}

fn main() -> Result<(), ()> {
    let introduce_error = 0;
    println!("Running test case...");
    let result = unsafe { testmain(introduce_error) };
    println!("Test ran (errors introduced: {}), result was {}", introduce_error, result);
    if (introduce_error == 0) == (result == 0) {
        Ok(())
    } else {
        Err(())
    }
}
