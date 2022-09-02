fn main() {
    cc::Build::new()
        .file("../cases/cryptobackend-aead.c")
        .include("../../src/include/")
        // FIXME: Build.
        // TBD: We could also use libcose, but then we'd have to replicate the mess that the
        // dependencies are in the Makefile here as well, and for what? Whoever runs this with Rust
        // as frontend likely also uses Rust backends.
        .include("../native/rustbuilthdr/")
        // FIXME: missing a few more ... but for AEAD it's really sufficient.
        .compile("case_cryptobackend_aead");
}
