@page demo_iotlab Demo: Pulling large amounts of data from a device at IoT Lab using block-wise transfer

In this demo,
an embedded board is set up and configured remotely in the [FIT/IoT-LAB](https://www.iot-lab.info/),
and a large collection of "sensor data" is is pulled from the device by a local computer.
Unlike the @ref demo_peertopeer "peer to peer demo",
this is an exchange between different CoAP and OSCORE implementations,
traverses the Internet,
and resembles a situation in which an embedded device is queried by a cloud service.

Preparation
-----------

* Before attempting to follow through this,
  please ensure to have all prerequisites installed as described on @ref demo_common.

* In addition, you have to [create an account at the IoT-LAB](https://www.iot-lab.info/testbed/signup),
  which can take some time as applications are verified manually.
  Your account must be provisioned with an SSH key,
  as described [in the SSH key tutorial](https://www.iot-lab.info/tutorials/ssh-access/).

  (If you can not use IoT-LAB, several steps in this need to be altered.
  The board name and flashing procedure will differ,
  [Ethernet-over-Serial](https://riot-os.org/api/group__drivers__ethos.html) or some other link needs to be set up,
  and there must be an IPv6 route from your computer to the board.)

* As the RIOT device only supports IPv6 in this setup,
  your computer needs to have a default IPv6 route.

Device setup
------------

* Inside the `tests/riot-tests/plugtest-server`, run

      $ make BOARD=iotlab-m3 all

  @note
  If you see an error like

      make: *** No rule to make target '.../../RIOT/Makefile.include'.  Stop.

  @note
  then the git repository was not cloned recursively. That can be fixed by a simple

      $ git submodule init
      $ git submodule updae

  This produces a file `bin/iotlab-m3/test_plugtest_server.elf`,
  which will be uploaded to the lab.

  Don't worry about its size:
  This can easily be several megabytes,
  as it contains lots of debug information that will not be flashed to the microcontroller.

* Inside FIT/IoT-LAB, configure a "New Experiment", which you could name "oscore_demo".
  For a first run, it's recommended that you take 45 instead of the default 20 minutes,
  which is primarily to avoid a frustrating experience when on top of anything going wrong,
  your experiment is cancelled just before you fixed it.

  At "Nodes", add one of type "M3 (At86rf231)" and add it to the experiment.

  This tutorial will assume you pick the Grenoble site.

  Add a firmware to the device by clicking the microchip icon and uploading the above .elf file.

  Submit the experiment, enter it, and wait for it to start (the display updates automatically).
  When it is running, make note of the node this is running on.
  It is displayed in the "nodes" column of the experiment view, and followed by ".grenoble.iot-lab.info" or similar.
  For the following commands, the name `m3-100` will be assumed.

* Log in to the Grenoble server from your computer:

      $ ssh USERNAME@grenoble.iot-lab.info

  If this does not work, verify that you have an SSH key available that is configured with IoT-LAB,
  and that the user name you used matches the one assigned by them.

  For the remainder of this sections, commands prefixed by `$` need to be entered into this session.

* Pick an IPv6 subnet and a TAP interface to use.

  The [IPv6 subnet list](https://www.iot-lab.info/tutorials/understand-ipv6-subnetting-on-the-fit-iot-lab-testbed/)
  enumerates the subnets usable for the respective lab locations.
  Pick one, and verify using `ip -br -6 a` that it is not in use on this server at the moment.

  For the example, we will be using `2001:660:5307:3100::/64`.

  In that list, you will also see the network interfaces in use.
  Pick a name for a TAP interface ("tap" followed by a small number) that is not currently in use either;
  the examples will use `tap0`.

* Set up a network and open a device console.

  Replace your device name (`m3-100`), the TAP interface (`tap0`) and the IP address (careful: this is an address out of the subnet, not the subnet itself!) and run:

      $ sudo ethos_uhcpd.py m3-100 tap0 2001:660:5307:3100::1/64

  This should show a lot of setup output,
  but eventually stop at `gnrc_uhcpc: uhcp_handle_prefix(): configured new prefix ...`.

  Press Return to trigger the shell prompt:

      >

  That is a RIOT command prompt, which you can verify by running

      > ifconfig
    Iface  8  HWaddr: 00:F1:8A:60:79:FF
              L2-PDU:1500 MTU:1500  HL:64  RTR
              RTR_ADV  Source address length: 6
              Link type: wired
              inet6 addr: fe80::2f1:8aff:fe60:79ff  scope: link  VAL
              inet6 addr: fe80::2  scope: link  VAL
              inet6 group: ff02::2
              inet6 group: ff02::1
              inet6 group: ff02::1:ff60:79ff
              inet6 group: ff02::1:ff00:2
    
    Iface  7  HWaddr: 11:15  Channel: 26  Page: 0  NID: 0x23
              Long HWaddr: 3A:5D:F9:65:10:6B:11:15
               TX-Power: 0dBm  State: IDLE  max. Retrans.: 3  CSMA Retries: 4
              AUTOACK  ACK_REQ  CSMA  L2-PDU:102 MTU:1280  HL:64  RTR
              RTR_ADV  6LO  IPHC
              Source address length: 8
              Link type: wireless
              inet6 addr: fe80::385d:f965:106b:1115  scope: link  VAL
              inet6 addr: 2001:660:5307:3100:385d:f965:106b:1115  scope: global  VAL
              inet6 group: ff02::2
              inet6 group: ff02::1
              inet6 group: ff02::1:ff6b:1115

  We can now add a usable IP address inside the subnet to the wired interface
  (usually, the only assigned one is on the wireless interface,
  and hairpin routing is not active):

      > ifconfig 8 add 2001:660:5307:3100::2/64

* Verify that you can ping that address from your computer.

  If you can not, make sure you have been using the same subnet in all previous lines.
  You can open an SSH session from a separate terminal and `ifconfig` to verify that still noone else is using the subnet on a different TUN or TAP interface.

Cryptography setup
------------------

* Back at your computer, a security context like this:

      $ mkdir context-with-iotlab
      $ echo '{"secret_ascii": "correct unicorn battery stable"}' > context-with-iotlab/secret.json
      $ echo '{"algorithm": "ChaCha20/Poly1305", "sender-id_hex": "42", "recipient-id_hex": "012345"}' > context-with-iotlab/settings.json
      $ echo '{"coap://[2001:660:5307:3100::2]/*": {"oscore": {"contextfile": "./context-with-iotlab/"}}}' > credentials.json

  This sets up a security context in a folder named "context-with-iotlab",
  which aiocoap will extend by sequence numbers and replay window state at runtime.

  It also sets up a credentials file which will be used by aiocoap to decide which security context to use when contacting the device.

* Inside the `tests/riot-tests/plugtest-server` directory, run the key derivation script to obtain an initial state for the device:

      $ ./oscore-key-derivation /path/to/.../context-with-iotlab/ --format RIOT --flip
      userctx 24 012345 - 2f9854baaf0fd487cf718450 4dc26f61be7b4bc30547b2dd227d6c8849e8f50f523c9612073880a1fc8b38fb 560def7740d0b6df059dad57da7dcd5b5aac5d4b27a9db211bb55dc0c0e17397

* Copy-paste that output into the running RIOT terminal.

  As the buffers of the Ethernet-over-Serial emulation are limited,
  should copy them in chunks, and press Ctrl-D (but not Return) after having pasted a part.
  Pasting everything up to the two hex large chunks (the keys), and those two separately, is usually sufficient.
  (It doesn't hurt to enter the separating blanks before and after the Ctrl-D).

  Pressing return in the end should give you a `>` prompt once more with no usage error message;
  it will be preceded by an initialization line you can use for a installment of the same demo.

  @warning It is important that such a key is only entered once into a device.
  If you want to use the same key for a follow-up experiment,
  keep an eye out for RIOT printing lines starting with "userctx":
  You can use the latest of those to start your next run.
  In a real application, this role would be taken by flash storage,
  and nonce reuse is not a real issue as long as our key is "correct unicorn battery stable",
  but let's not get into bad habits.

.

Fetching data
-------------

* Showtime: Run

      $ aiocoap-client 'coap://[2001:660:5307:3100::2]/sensordata' --credentials credentials.json

  and observe that a comparatively large (\> 1kB) amount of what could plausibly be sensor data was transferred.

* When you run it again, append `-vv` to the command line. This will enable verbose output,
  which shows how individual blocks of data are exchanged in lockstep.

If you run a network monitor like [Wireshark](https://www.wireshark.org/) on your own network interface
and use the filter expression "coap",
you can monitor the encrypted CoAP messages.
The messages are recognizable as request / response pairs,
but the "sensordata" path and the payload are protected,
as is the block number (because this example is running in "inner block-wise" mode).
You can see the increasing sequence numbers encoded in the OSCORE option
(even though it is currently not recognized in Wireshark),
and if you vary the context's "sender-id_hex" field,
you can recognize that value inside the option as well.

@note
When you experiment with the client's sender ID in this demo,
avoid picking the empty ID.
That ID is used by the plug test server,
which takes precedence over the custom context set up on the command line.
