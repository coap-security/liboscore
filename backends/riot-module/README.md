@page backend_riot_module Build system integration for RIOT-OS

Integration into the build system of the RIOT operating system is provided as
an [external module](https://riot-os.org/api/creating-modules.html#modules-outside-of-riotbase)
shipped in `backends/riot-module`.

It can be pulled into a module by adding the lines

    EXTERNAL_MODULE_DIRS += path-to-liboscore/backends/riot-module
    USEMODULE += oscore
    USEMODULE += libcose_crypt_monocypher

to an application's Makefile.

It combines a set of backends (light integration for nanocoap and libcose), and
adds their source files and dependencies to the build.

The `libcose_crypt_monocypher` line selects libcose's cryptography backend. Any
libcose backend (or combination thereof) can be selected as long as it provides
the AEAD algorithms needed for the selected ciphers. See [the libcose RIOT
documentation](https://riot-os.org/api/group__pkg__libcose.html) for details.
