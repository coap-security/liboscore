@page demo_plugtest_linux Demo: Running the OSCORE plug test server on RIOT native

This guide walks you through a demo of libOSCORE
where a plugtest server written using libOSCORE
is run on the ["native" port of RIOT-OS](https://github.com/RIOT-OS/RIOT/wiki/Family:-native).
In the native port, applications run as single processes on a UNIX system,
and many peripherals otherwise found as microcontroller components are emulated.
In particular, a [TAP](https://en.wikipedia.org/wiki/TUN/TAP) device is used
to connect the host and the native board via an simulated Ethernet link.

In the course of the demo,
a plugtest client written in Python is used to interact with that server.

The plugtest runs on a static context and consists of several correct and incorrect uses of OSCORE.
These are described in numbered test cases [in the latest plugtest description](https://ericssonresearch.github.io/OSCOAP/test-spec5.html).

Before attempting to follow through this,
please ensure to have all prerequisites installed as described on @ref demo_common.

* Set up a local network TAP network interface:

  Inside `tests/riot-tests/RIOT/dist/tools/tapsetup`, run `./tapsetup`.

  This creates two TAP devices (`tap0` and `tap1`) and connects them to an emulated switch (`tapbr0`). This is RIOT's default network setup for the native port, but (while convenient for variations on the demos) only means that from a host point of view, you will be seeing the plugtest server on the `tapbr0` interface.

* Inside `tests/riot-tests/plugtest-server`, run `make all term`.

  This builds the plugtest server and runs it, providing you with the RIOT shell prompt. Try it out by running `help`!

* In the RIOT prompt, run `ifconfig`, which should result in output like this:

      > ifconfig
      ifconfig
      Iface  6  HWaddr: 3E:63:BE:85:CA:96
                L2-PDU:1500 MTU:1500  HL:64  Source address length: 6
                Link type: wired
                inet6 addr: fe80::3c63:beff:fe85:ca96  scope: link  VAL
                inet6 group: ff02::1
                inet6 group: ff02::1:ff85:ca96

  This indicaes the virtual device's link-local address in the `inet6 addr` line.
  Try it out by using `ping fe80::3c63:beff:fe85:ca96%tapbr0` (with the right address substituted in) from the host!

The server side is now prepared and ready; leave that running and switch over to your aiocoap check-out.

* As the plug test prescribes the use of AES-CCM which is not availble in RIOT-OS's default COSE implementation,
  change the algorithm setting in `contrib/oscore-plugtest/common-context/*/settings.json` from "AES-CCM-16-64-128" to "ChaCha20/Poly1305".
* Run the plug test client:

      $ ./contrib/oscore-plugtest/plugtest-client '[fe80::3c63:beff:fe85:ca96%tapbr0]' /tmp/clientctx

  with the appropriate link-local address.

  The directiory `/tmp/clientctx` does not need any special preparation –
  this is just the place where the plug test client will persist its security context.
  This allows you to run it several times without running into the libOSCORE server's replay detection,
  which would trigger if the plug test's static security context were re-initialized on every client invocation.

* The plug test client runs an interactive prompt that lets you run the various test cases number by number.
  Just pressing Enter will run the next test
  (unless you already manually requested the current test to be repeated; in that case it runs the same again).

  The following tests are notworthy:

  * 0: This runs an unprotected GET without OSCORE to establish a base line.

    If this fails, verify that you are using the correct address (including zone identifier),
    and that the previous ping test succeeds.

  * 1: This is the first elementary OSCORE test.

    If this fails, verify that you changed the encryption algorithm as in the previous step.
    Make sure to remove the `/tmp/clientctx` folder after any updates to the common context.

  * 5-7: These are about observation, and currently fail spectacularly.

    Please skip them until [#12736](https://github.com/RIOT-OS/RIOT/issues/12736) is fixed.

  * 12-15: These test for incorrect use of OSCORE.

    Don't be irritated by error codes or the word "failed" in the outputs,
    as long as they are in lines starting with 'Check passed'.

  * 16 and 17: These fail because the plugtest description is assuming a very particular model of operation
    (that the same resource tree is available with and without OSCORE,
    but that opportunistic encryption is inacceptable)
    that is not aligned with the intermediate integration model of the plugtest server.


From here, you can explore the remaining demos.
As the plug test firmware also hosts the remaining demo code,
you can adapt the other demos to run on the native board as well.
The conveniently set up TAP bridge `tapbr0` will assist in connecting two concurrent executions of the program.
