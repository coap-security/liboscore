use std::path::PathBuf;
use std::env;
use std::io::Write;

fn main() {
    // Copied from ../cases/Makefile.include, and limited one by one as we start supporting them
    let cases = [
        "cryptobackend-aead",
//         "standalone-demo",
//         "unprotect-demo",
        "unit-contextpair-window",
        "cryptobackend-hkdf",
    ];

    let mut testmain_functions = Vec::new();

    let mut basebuilder = cc::Build::new();
    let basebuilder = basebuilder
        .include("../../src/include/")
        // FIXME: Build.
        // TBD: We could also use libcose, but then we'd have to replicate the mess that the
        // dependencies are in the Makefile here as well, and for what? Whoever runs this with Rust
        // as frontend likely also uses Rust backends.
        .include("../native/rustbuilthdr/")

        // Let's use a known simple mock backend for starters...
        .include("../../backends/mockoap/inc/")

        // FIXME: missing a few more ... but for the current tests that's sufficient
        // and all the files we need, piece by piece, eg for the contextpair window test
        .file("../../src/contextpair.c")
        ;

    for case in cases {
        // Not that we'd particularly care -- they just need to be distinct.
        let output_name = format!("case_{}", case);

        // Renaming testmain to testmain_something so we can have them all in a single binary
        let testmain_newname = format!("testmain_{}", case.replace("-", "_"));
        let testmain_redefined = format!("-Dtestmain={}", testmain_newname);
        testmain_functions.push(testmain_newname);

        basebuilder.clone()
            .flag(&testmain_redefined)
            // Test cases use these a lot (for describing their starting conditions) and just rely
            // on the rest being zero as required by the standard
            .flag("-Wno-missing-field-initializers")
            .file(format!("../cases/{}.c", case))
            .compile(&output_name);
    }

    // A file containing all the extern functions and a list of cases
    let testmain_list = PathBuf::from(env::var("OUT_DIR").unwrap()).join("testmain-list.rs");

    let mut outfile =
        std::fs::File::create(&testmain_list).unwrap();

    writeln!(outfile, "extern \"C\" {{").unwrap();
    for tmf in &testmain_functions {
        writeln!(outfile, "fn {}(introduce_error: i32) -> i32;", tmf).unwrap();
    }
    writeln!(outfile, "}}").unwrap();

    writeln!(outfile, "static TESTMAINS: [(&'static str, unsafe extern \"C\" fn(i32) -> i32); {}] = [", testmain_functions.len()).unwrap();
    for tmf in &testmain_functions {
        writeln!(outfile, "(\"{}\", {}),", tmf, tmf).unwrap();
    }
    writeln!(outfile, "];").unwrap();
    outfile
        .sync_all()
        .unwrap();
}
