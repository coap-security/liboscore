use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let rustbuilthdr_base = PathBuf::from(env::var("OUT_DIR").unwrap()).join("rust-built-headers");
    run_cbindgen(&rustbuilthdr_base);
    println!(
        "cargo:PLATFORMHEADERS={}",
        rustbuilthdr_base
            .to_str()
            .expect("Please use paths tha are also strings")
    );

    let liboscore_includes = Path::new("c-src/include/");
    // Err out early to get a clearer error message
    assert!(
        liboscore_includes.join("oscore/message.h").exists(),
        "libOSCORE headers are not avaialble at {}",
        liboscore_includes.display()
    );
    assert!(
        rustbuilthdr_base.join("oscore_native/msg_type.h").exists(),
        "libOSCORE platform headers are not avaialble at {}",
        rustbuilthdr_base.display()
    );
    run_bindgen(liboscore_includes, &rustbuilthdr_base);

    bundle_staticlib(&rustbuilthdr_base)
}

fn run_bindgen(liboscore_include: &Path, platform_include: &Path) {
    bindgen::Builder::default()
        // On LLVM 18 (at least 1:18.1.8-11 as shipped in Debian), stdint.h appears to be a no-op
        // unless a proper C standard is defined. Weird, but no harm in declaring it, and works
        // around <https://github.com/rust-lang/rust-bindgen/issues/1229> /
        // <https://gitlab.com/oscore/liboscore/-/issues/61>
        .clang_arg("-std=c99")
        .clang_arg(format!("-I{}", liboscore_include.to_str().unwrap()))
        .clang_arg(format!("-I{}", platform_include.to_str().unwrap()))
        // FIXME: This is practically required for bindgen output to contain any functions when
        // built for wasm32-unknown-unknown -- might need a more proper solution (but this is a
        // good workaround from <https://github.com/rust-lang/rust-bindgen/issues/751>).
        .clang_arg("-fvisibility=default")
        .use_core()
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
        .allowlist_function("oscore_crypto_aead_get_ivlength")
        .allowlist_function("oscore_prepare_request")
        .allowlist_function("oscore_encrypt_message")
        .allowlist_function("oscore_msg_protected_trim_payload")
        .allowlist_function("oscore_msg_protected_append_option")
        .allowlist_function("oscore_msg_protected_set_code")
        .allowlist_function("oscore_release_unprotected")
        .allowlist_function("oscore_prepare_response")
        .allowlist_function("oscore_msgerr_native_is_error")
        .allowlist_function("oscore_msg_native_map_payload")
        .allowlist_function("oscore_unprotect_response")
        .allowlist_type("oscore_msgerr_protected_t")
        .allowlist_type("oscore_msg_protected_t")
        .allowlist_type("oscore_msg_protected_optiter_t")
        .allowlist_type("oscore_unprotect_request_result")
        .allowlist_type("oscore_context_primitive")
        .allowlist_type("oscore_context_primitive_immutables")
        .allowlist_type("oscore_")
        .allowlist_var("OSCORE_KEYIDCONTEXT_MAXLEN")
        .allowlist_var("IV_KEYID_UNUSABLE")
        .allowlist_var("OSCORE_KEYID_MAXLEN")
        .allowlist_var("PIV_BYTES")
        .allowlist_var("OSCORE_CRYPTO_AEAD_IV_MAXLEN")
        .header("oscore_all_headers.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed")
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("writing bindings.rs failed");
}

fn run_cbindgen(rustbuilthdr_base: &Path) {
    let rustbuilthdr_dir = rustbuilthdr_base.join("oscore_native");
    std::fs::create_dir_all(&rustbuilthdr_dir).unwrap();

    let cratedir_cryptobackend;
    let cratedir_msgbackend;
    if std::env::current_dir().unwrap().file_name() == Some(std::ffi::OsStr::new("liboscore")) {
        cratedir_cryptobackend = "../../rust/liboscore-cryptobackend";
        cratedir_msgbackend = "../../rust/liboscore-msgbackend";
    } else {
        // FIXME: Reaching over to those places is brittle at best. Keeping it in for the 0.1.0 to
        // stay compatible in the over-all crate layout with the version used in coap-ace-poc for
        // some time.
        cratedir_cryptobackend = "../liboscore-cryptobackend-0.1.0";
        cratedir_msgbackend = "../liboscore-msgbackend-0.1.0";
    }

    cbindgen::Builder::new()
        .with_crate(cratedir_cryptobackend)
        .with_config(
            cbindgen::Config::from_file(format!("{cratedir_cryptobackend}/cbindgen.toml")).unwrap(),
        )
        .generate()
        .expect("Failure generating cbindgen headers for the cryptobackend")
        .write_to_file(rustbuilthdr_dir.join("crypto_type.h"));

    cbindgen::Builder::new()
        .with_crate(cratedir_msgbackend)
        .with_config(
            cbindgen::Config::from_file(format!("{cratedir_msgbackend}/cbindgen.toml")).unwrap(),
        )
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("Failure generating cbindgen headers for the msgbackend")
        .write_to_file(rustbuilthdr_dir.join("msg_type.h"));
}

fn bundle_staticlib(rustbuilthdr_base: &Path) {
    cc::Build::new()
        .include("c-src/include/")
        .include(".")
        .include(rustbuilthdr_base.to_str().unwrap())
        .file("c-src/contextpair.c")
        .file("c-src/oscore_message.c")
        .file("c-src/protection.c")
        .file("c-src/context_primitive.c")
        .compile("liboscore_static_objects");
}
