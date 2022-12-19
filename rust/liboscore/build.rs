use std::path::{Path, PathBuf};
use std::env;
use std::io::Write;

fn main() {
    let rustbuilthdr_base = PathBuf::from(env::var("OUT_DIR").unwrap()).join("rust-built-headers");
    run_cbindgen(&rustbuilthdr_base);
    println!("cargo:PLATFORMHEADERS={}", rustbuilthdr_base.to_str().expect("Please use paths tha are also strings"));

    run_bindgen(Path::new("../../src/include/"), &rustbuilthdr_base);

    bundle_staticlib(&rustbuilthdr_base)
}

fn run_bindgen(liboscore_include: &Path, platform_include: &Path) {
    bindgen::Builder::default()
        .clang_arg(format!("-I{}", liboscore_include.to_str().unwrap()))
        .clang_arg(format!("-I{}", platform_include.to_str().unwrap()))

        // Not sure why exactly these conflict, but we don't need them
        .derive_copy(false)
        .derive_debug(false)
        // It's Rust code that defines them, and we're building it in the same process, so let's
        // avoid redefinitions
        .blocklist_type("oscore_msg_native_t")
        .blocklist_type("oscore_msgerr_native_t")
        .blocklist_type("oscore_crypto_aead_decryptstate_t")
        .blocklist_type("oscore_crypto_aead_encryptstate_t")
        .allowlist_function("oscore_cryptoerr_is_error") // a bit weird, this should be directly
                                                         // importable (but the renaming makes it
                                                         // weird)
        .allowlist_function("oscore_msg_protected_get_code")
        .allowlist_function("oscore_msg_protected_map_payload")
        .allowlist_function("oscore_msgerr_protected_is_error")
        .allowlist_function("oscore_unprotect_request")
        .allowlist_function("oscore_oscoreoption_parse")
        .allowlist_function("oscore_crypto_aead_from_number")
        .allowlist_function("oscore_crypto_hkdf_from_number")
        .allowlist_function("oscore_msg_protected_optiter_init")
        .allowlist_function("oscore_msg_protected_optiter_next")
        .allowlist_function("oscore_msg_protected_optiter_finish")
        .allowlist_function("oscore_context_primitive_derive")
        .allowlist_type("oscore_msgerr_protected_t")
        .allowlist_type("oscore_msg_protected_t")
        .allowlist_type("oscore_msg_protected_optiter_t")
        .allowlist_type("oscore_unprotect_request_result")
        .allowlist_type("oscore_context_primitive")
        .allowlist_type("oscore_context_primitive_immutables")

        .header("oscore_all_headers.h")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("bindgen failed")
            .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
            .expect("writing bindings.rs failed");
}

fn run_cbindgen(rustbuilthdr_base: &PathBuf) {
    let rustbuilthdr_dir = (&rustbuilthdr_base).join("oscore_native");
    std::fs::create_dir_all(&rustbuilthdr_dir).unwrap();

    let exitcode = std::process::Command::new("cbindgen")
        .arg("--lang=C")
        .current_dir("../../rust/liboscore-cryptobackend")
        .stdout(std::fs::File::create(rustbuilthdr_dir.join("crypto_type.h")).unwrap())
        .status()
        .expect("Failed to run cbindgen for cryptobackend headers");
    // Simplification after exit_status_error is stable <https://github.com/rust-lang/rust/issues/84908>
    //         .exit_ok()
    //         .expect("cbindgen for cryptobackend returned unsuccessfully");
    assert!(exitcode.success(), "cbindgen for cryptobackend returned unsuccessfully");

    let exitcode = std::process::Command::new("cbindgen")
        .arg("--lang=C")
        .current_dir("../../rust/liboscore-msgbackend")
        .stdout(std::fs::File::create(rustbuilthdr_dir.join("msg_type.h")).unwrap())
        .status()
        .expect("Failed to run cbindgen for msg headers");
    // Simplification after exit_status_error is stable <https://github.com/rust-lang/rust/issues/84908>
    //         .exit_ok()
    //         .expect("cbindgen for msg returned unsuccessfully");
    assert!(exitcode.success(), "cbindgen for msg returned unsuccessfully");
}

fn bundle_staticlib(rustbuilthdr_base: &Path) {
    cc::Build::new()
        .include("../../src/include/")
        .include(rustbuilthdr_base.to_str().unwrap())
        .file("../../src/contextpair.c")
        .file("../../src/oscore_message.c")
        .file("../../src/protection.c")
        .file("../../src/context_primitive.c")
        .compile("liboscore_static_objects");
}
