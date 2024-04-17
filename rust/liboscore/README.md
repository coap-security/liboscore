This is the main crate of libOSCORE when accessing libOSCORE through Rust.

It performs different tasks that are relatively tightly coupled:
* It builds the C header files for the Rust backend implementations using cbindgen.
* It configures and builds Rust "header" files from the C header files (excluding types that are already native Rust types), as a `-sys` crate would do.
* It compiles the C files of liboscore directly for static linking.
* It implements coap-message on top of OSCORE protected messages.

At present, it pulls in both the cryptography and the message backends written in Rust (liboscore-cryptobackend and liboscore-msgbackend).
Making the cryptography backend optional would be simple and straightforward
(and is just waiting for an application to need it).
Using an non-Rust message backend would be possible in theory,
but the author fails to imagine when that would be useful.
Some extra constructors for protected messages might be needed.
