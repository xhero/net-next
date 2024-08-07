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

The LocalTalk netweork implemented one of the phisical layers for the
AppleTalk, using an RS422 bus, with FM0 and SDLC encoding, and on Macs
it was managed using the build-in Zilog SCC Z8530. In the modern world,
the required interface is implemented using TashTalk, which then
communicates to a PC via a serial port or serial adapter, or a specialized
adapter (https://github.com/xhero/USB2LT) to directly connect an LocalTalk
network via an USB port. Since support for LocalTalk is still present
in the Kernel, it is then possible to user Netatalk 2 (or the upcoming
version 4) out of the box. The interface is also compatibile with
macipgw (https://github.com/jasonking3/macipgw) to provide MacIP over
Localtalk.
This driver implements a Line Discipline which must be attached and
then the LocalTalk interface can be brought up and used.

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
    lt1 -seed -phase 2 -net 2 -addr 2.128 -zone "LocalTalk

And also different type of adapters (like Ethernet) can be mixed in
the Netatalk routing.

Debug
-----

Despite the name, tcpdump is able to understand DDP and basic AppleTalk packets:

    sudo tcpdump -i lt0 -vvvX

The driver can also be recompiled settin the TASH_DEBUG option, to have a more
verbose log of what is going on.