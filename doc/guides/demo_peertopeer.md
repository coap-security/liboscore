@page demo_peertopeer Demo: Peer-to-peer exchanges in 6LoWPAN network

In this demo,
two [Particle Xenon boards](https://docs.particle.io/xenon/) are set up in a single 6LoWPAN network
and toggle each other's LEDs from their buttons.

Before attempting to follow through this,
please ensure to have all prerequisites installed as described on @ref demo_common.

* Plug in the first board while keeping the "Mode" button pressed (or press the "Reset" button briefly while keeping Mode pressed).

  The board will blink purple for some time, then start blinking yellow. Release the Mode button.

  The board has now booted into its built-in USB DFU bootloader software.

  If all is set up correctly,
  `dfu-util --list`
  will show several "Found DFU" lines;
  if not, check whether you installed the udev rules in @ref demo_common.

  This step should *only* be necessary the first time you flash this onto your particle;
  once in place, later firmware uploads can send the device into DFU mode automatically.

* Inside `tests/riot-tests/plugtest-server`, run `make BOARD=particle-xenon PARTICLE_MONOFIRMWARE=1 PORT=/dev/ttyACM0 all flash term`.

  This builds the plug test server
  (which also contains the other demos),
  uploads it via DFU,
  and gives you terminal access.

  If this gives you a "Device or resource busy" error,
  something else has just started interacting with the board.
  This commonly happens with older versions of ModemManager,
  and is little more than a nuisance –
  after a few seconds,
  ModemManager will relinquish the device again.

  If you see errors like "Permission denied: '/dev/ttyACM0'", unplug all boards and check whether a `/dev/ttyACM0` exists.
  If so, watch the `/dev` directory as you plug in your boards,
  and substitute the device name accordingly.
  In some operating systems, you may need to help yourself to permissons on those device files,
  often by becoming member of the "plugdev" or "dialout" group.

  Eventually, the terminal program will indicate readiness by printing "Welcome to pyterm!".
  You may need to press return to flush out any remaining commands ModemManager tried to send,
  and eventually will be presented with a RIOT prompt (`>`).

  Try `help` and have a look around the system!

* Repeat the first steps for the second board: enter the bootloader, flash, and open a terminal – this time at `/dev/ttyACM1`.

Once your boards are flashed, you can unplug and replug them at any time
without the need to flash them again.
Beware that their TTY device names are not persistent,
and are usually assigned by assigning the first currently unused one.

* Run `ifconfig` on both devices.

  They will be showing two devices,
  one with "Link type: wired" (which we'll ignore for this demo)
  and one with "wireless",
  which is a 6LoWPAN interface with default settings we will use.

  Verify over-the-air connectivity between the devices by issuing a command like

      > ping6 fe80::cd30:8ef6:582b:14c6%9

  where the IP address up to the "`%`" sign is the address of the *other* board,
  and the number after it (the zone identifer) is the wireless interface number of the *own* ifconfig list.

  Three successful pings should be reported, along with their signal strength.

* In order to talk OSCORE, we'll need to set up a shared security context.
  In a real-world scenario, this could be established by a [LAKE](https://datatracker.ietf.org/wg/lake/about/) like [EDHOC](https://tools.ietf.org/html/draft-selander-lake-edhoc-00);
  until that is available, we'll set it up manually:

  Prepare a folder (called `/tmp/p2p-context` here) containing two files:

  secret.json: `{"secret_ascii": "correct horse battery staple"}`

  settings.json: `{ "algorithm": "ChaCha20/Poly1305", "sender-id_hex": "03", "recipient-id_hex": "02" }`

  These follow the security context description format of aiocoap, which is used to shape the keys into an easy-to-enter form,
  and to derive the keys until the HKDF steps of the currently used libcose are available.

  Run the key derivation script twice like this:

      $ tests/riot-tests/plugtest-server/oscore-key-derivation /tmp/p2p-context --format RIOT
      $ tests/riot-tests/plugtest-server/oscore-key-derivation /tmp/p2p-context --format RIOT --flip

  and copy the respective outputs to the two terminals.

  Note that these contexts can not be used twice, as doing so results in nonce reuse and thus cryptographic doom.
  Before you enter any of that again, please modify the secret and distribute the new security contexts.

  Security contexts are written to ROM inside the device,
  and persist through reboots until reconfigured or the firmware is uploaded again.

  @warning
  There is currently an unresolved issue with the data being persisted
  in a place where firmware checksumming is applied on the Particle Xenon board;
  most other boards and programming methods should be fine.
  With affected boards, any persisted data result in a failure to start up,
  rendering the firmware inoperable after a reboot, and requiring a reflash.
  This is tracked as https://gitlab.com/oscore/liboscore/-/issues/49.

* In order to find a usable destination address,
  you'll need to tell the boards which LEDs to switch.
  This is done by entering

      > target fe80::cd30:8ef6:582b:14c6 9 5683

  in the command prompt, where the IP address is the other board's and the zone identifier is the own as with the ping earlier.
  This will configure the "on" and "off" commands to act on that address,
  in particular its `/light` resource that will receive plain "0" and "1" values.

  Like the security context,
  the target address is persisted in ROM.

* Showtime: Toggle the other device's LEDs with

      > on
      > off

* At any time, you can also press the "MODE" button:
  At the time it gets pressed, an "on" is sent;
  when it is released, an "off" is sent.

Detached mode
-------------

Both the security context and the target address
are persisted in the flash memory of the devices;
the former using a @ref oscore_context_b1.

This allows a board that is configured once to be shown off toggling the other board's LED
from a battery attached to the battery connector
or from a USB power supply.
(Power banks are not ideal, as they often shut down when too little current is drawn).

Beware that the demo uses reliable transmission,
which can keep a device busy even when the state they are trying to transmit is not even current any more.
This allows showing behaviors of retransmission,
but is something to be aware of when doing live demos,
especially when the receiving node is offline for long enough for retries to get more sparse.

When boards power up again, parts of their security contexts are not initialized or recovered,
so it takes failing attempts to recover them.
Real-world applications that try to get things done as quickly as possible
would probably employ retransmission or initialize eagerly;
in the demo, these mechanisms are left out for simplicity and for visibility.
