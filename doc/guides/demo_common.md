@page demo_common Common set-up instructions for RIOT-based demos

This guide shows the installation steps for common prerequisites for running any of the RIOT base demo applications.
It assumes familiarity with the common installation mechanisms of the operating system.

While RIOT and this library can be built on several platforms,
including Windows and macOS,
but RIOT's native port is only supported on some UNIX-like systems.
Thus (and for general simplicity),
the guides will assume Linux as the operating system, and a x86-based platform.

The instructions are generic on Linux distributions, but also contain specific information relevant to Debian users.
If you have yet to make a choice on which operating system to run the demos,
[Debian 10 (Buster) or newer](https://www.debian.org/distrib/netinst) is recommended.
Most will apply to Ubuntu just the same, but please note that the ARM GCC shipped with Ubuntu Bionic is [**not** supported in RIPT](https://github.com/RIOT-OS/RIOT/pull/10404); later versions work fine.

Some demos use [Particle Xenon boards](https://docs.particle.io/xenon/) for hands-on experience.
The board has been [deprecated by its vendor](https://blog.particle.io/2020/01/28/mesh-deprecation/),
but its usability with RIOT-OS is not expecetd to suffer from that.
They can generally be replaced with any other network capable [RIOT board](https://riot-os.org/api/group__boards.html);
for flashing instructions and any installation prerequisites, follow the board's description.

* Ensure that `git` is installed
* Clone the libOSCORE repository:

      $ git clone --recursive https://gitlab.com/oscore/liboscore.git

  This will also check out a copy of RIOT-OS in a subdirectory.

* Install a native C compiler as well as a C compiler and any debugger necessary for your physical demo board.

  [The RIOT instructions](https://github.com/RIOT-OS/RIOT/wiki/Setup-a-Build-Environment) cover this only on a very generic level.
  For the demos' exemplary platforms, you should install:

  * The GCC toolchain for ARM Cortex-M3 ([as per RIOT's instructions](https://github.com/RIOT-OS/RIOT/wiki/Family:-ARM))
  * The [`dfu-util` bootloader as described by Particle](https://docs.particle.io/support/particle-tools-faq/installing-dfu-util/#activating-dfu-mode-blinking-yellow-) bootloader
  * A native GCC toolchain
  * Tools used in the build process: GNU Make, Python 3 and pyserial.

  Debian users can set all of this up by running

      $ sudo apt install gcc make gcc-arm-none-eabi gdb-multiarch binutils-multiarch dfu-util python3-serial
      $ sudo -e /etc/udev/rules.d/50-particle.rules

  and entering there:

      # UDEV Rules for flashing Particle boards without root privileges
      #
      # Core
      SUBSYSTEMS=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="607[df]", GROUP="plugdev", MODE="0660"
      # Photon/P1/Electron
      SUBSYSTEMS=="usb", ATTRS{idVendor}=="2b04", ATTRS{idProduct}=="[cd]00?", GROUP="plugdev", MODE="0660"
      #
      # See https://docs.particle.io/assets/files/50-particle.rules for origin and details

* Install aiocoap:

      $ git clone https://github.com/chrysn/aiocoap
      $ cd aiocoap
      $ pip3 install --user --upgrade ".[linkheader,oscore,prettyprint]"

  This is using a local installation of aiocoap because it will allow running the plug tests that are only available in the source repository and not part of the library shipped via PyPI.

That being set up, run see those pages for the actual demos:

* @ref demo_plugtest_linux
* @ref demo_peertopeer
* @ref demo_iotlab
