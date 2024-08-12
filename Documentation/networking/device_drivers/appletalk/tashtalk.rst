.. SPDX-License-Identifier: GPL-2.0

tashtalk.c: LocalTalk driver for Linux
======================================

Authors
-------

Rodolfo Zitellini <rwz@xhero.org>

Motivation
----------

The Linux Kernel includes a complete implementation of AppleTalk,
which can be used with the Netatalk package to share files with older
classic Macintoshes. The Kernel also contained drivers for LocalTalk,
the serial LAN found on many early Macs, which was based on older ISA
cards implementing the same chipset found in Macs. These boards were
historically very difficult to obtain, making LocalTalk on Linux
impractical. In recent years, a vibrant community of enthusiasts has
produced many tools to ease connecting older machines to the modern
world. One such project is TashTalk, which implements LocalTalk on a
PIC microcontroller (https://github.com/lampmerchant/tashtalk).

This driver reintroduces LocalTalk support to the Kernel by providing
an interface to TashTalk, which can be easily used over a serial port.
It comes handy for use with older machines that have no thernet option,
since all early Macintoshes had LocalTalk built-in.

Introduction
------------

The LocalTalk network implemented one of the physical layers for AppleTalk,
utilizing an RS422 bus with FM0 and SDLC encoding. On Macs, it was managed
by the built-in Zilog SCC Z8530. In the modern context, this interface is
provided by TashTalk, which communicates with a PC via a serial port or
adapter, or through a specialized adapter (https://github.com/xhero/USB2LT)
that directly connects a LocalTalk network via a USB port.

Since LocalTalk support is still present in the Linux kernel, it is possible
to use Netatalk 2 (or the upcoming version 4) directly. The interface is also
compatible with macipgw (https://github.com/jasonking3/macipgw) to provide
MacIP over LocalTalk.

This driver implements a line discipline that must be attached, after which
the LocalTalk interface can be brought up and used.

Operation/loading of the driver
-------------------------------

If the driver is compiled as module, it can be loaded with

    modprobe tashtalk

By default, 32 TashTalk adapters are available, so this means it can use
up to 32 serial ports. This number can be changed with the tash_maxdev
parameter.

Once the driver is loaded, the line discipline is used to attach a serial
port to it:

    sudo stty -F /dev/ttyUSB0 crtscts
    sudo ldattach -s 1000000 31 /dev/ttyUSB0

The line discipline ID for TashTalk is 31. Use of stty is required for
hardware flow control (and has to be properly implemented in hardware!)
Once the line disc is attached, the interface should be brought up:

    sudo ip link set dev lt0 up

or

    sudo ifconfig lt0 up

Any number (up to the specified max devices) of lt interfaces can be
used, which will be numbered lt0-ltN

Configuring Netatalk
--------------------

Netatalk natively supports Localtalk networks. Here is a simple
configuration for one network:

    lt0 -router -phase 2 -net 54321 -addr 54321.129 -zone LocalTalk

This sets the node id to 129, but the node id will still be arbitrated
on the network following the specifications. Starting Netatalk will then
make shares and printers available on the Localtalk network.
Multiple adapters can be used together:

    lt0 -seed -phase 2 -net 1 -addr 1.129 -zone "AirTalk"
    lt1 -seed -phase 2 -net 2 -addr 2.130 -zone "LocalTalk"

And also different type of adapters (like Ethernet) can be mixed in
the Netatalk routing.

Addressing
----------

LocalTalk addresses are dynamically assigned by default. In the Linux
implementation, a user program must request a preferred address, which
the driver will attempt to allocate. If the preferred address is unavailable,
the driver will suggest a new, randomly generated one, as specified by the
LocalTalk protocol. The user program should then retrieve the assigned address.

In the COPS LocalTalk implementation, this process was handled in a blocking
manner, and Netatalk continues to expect this behavior. The same approach is
implemented in this driver. When the user program issues a `SIOCSIFADDR` ioctl,
it triggers the address arbitration algorithm. The ioctl call will only return
once the arbitration is complete. Subsequently, a `SIOCGIFADDR` ioctl is required
to obtain the actual assigned address.


Debug
-----

Despite the name, tcpdump is able to understand DDP and basic AppleTalk packets:

    sudo tcpdump -i lt0 -vvvX

The driver can also be recompiled setting the TASH_DEBUG option, to have a more
verbose log of what is going on.

`print_hex_dump_bytes` is used to print incoming and outgoing packets

    echo 'file tashtalk.c line 231 +p' > /sys/kernel/debug/dynamic_debug/control

Please consult the current source for the exact line numbers.

Credits
-------

Many thanks to Tashtari (https://github.com/lampmerchant) for his TashTalk
implementation of LocalTalk, as well as his invaluable assistance in debugging this
driver and his unwavering support throughout the project.

Special thanks to Doug Brown for his invaluable help, patience, thorough reviews,
and insightful comments on my code, as well as his support throughout the
submission process.