# Using Linux for Zodiac FX development

Zodiac FX is an
[OpenFlow](https://www.opennetworking.org/sdn-resources/openflow)
software-defined networking switch developed by
[Northbound Networks](http://northboundnetworks.com/). The Zodiac FX
uses an
[Atmel SAM4E](http://www.atmel.com/products/microcontrollers/arm/sam4e.aspx)
system-on-chip. Software for this
[ARM Cortex-M4](http://www.arm.com/products/processors/cortex-m/cortex-m4-processor.php)
CPU is usually developed using the
[Atmel Studio](http://www.atmel.com/tools/atmelstudio.aspx) integrated
development environment. This IDE is a modification of Microsoft's
[Visual Studio](https://www.visualstudio.com/), using ARM Ltd's port
of the [GNU Compiler Collection](https://gcc.gnu.org/) as the compiler
and linker rather than using Microsoft's Visual C++ compiler (which
supports only Intel x86, AMD64 and DEC Alpha CPUs). The
Microsoft-originated Atmel Studio requires the
[Microsoft Windows](https://www.microsoft.com/en-us/windows) operating
system.

POSIX variants — such as Linux distributions — are a more natural home
for GCC. So much so that Ubuntu is the development platform for ARM
Ltd's work tuning GCC for their CPUs.

Your author does not own a Windows computer. His children do, but they
are of no mind to allow their gaming platform to be upset by USB and
JTAG drivers. Like many people in this fix, I bought a Raspberry Pi 3
as a computer where I can make errors without social or workplace
consequences.

The rest of this document is an exposition of the development cycle
for the Zodiac FX on a Debian computer. The instructions are readily
transferrable to other Linux distributions which have a GNU-inspired
user programs.

## Building the binary image

### Install ARM Ltd's port of GNU Compiler Collection

ARM Ltd have a variant of the GCC C and C++ compiler which they
maintain for cross-compiling to ARM embedded systems. This can be
found in the Ubuntu PPA team-gcc-arm-embedded. Other Linux
distributions typically pick up the source code from here.

Under Debian Jessie say

```sh
sudo apt-get install binutils-arm-none-eabi gcc-arm-none-eabi gdb-arm-none-eabi  libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib
```

A future version of Debian might change these packages' names to
…-arm-embedded to track the name change in Ubuntu.

The version in Debian Testing more closely follows the releases in
Ubuntu, making Testing the first recourse upon a compiler bug.

### Install GNU make

Make is a program for building binaries from source code projects.

Under Debian say

```sh
sudo apt-get install make
```

A special embedded version of make is not needed, as make runs
entirely on the computer, not on the ZodiacFX's system-on-chip.

### Install git

Git is a program for source code configuration control. The Zodiac FX
source code can be found on
[GitHub](https://github.com/NorthboundNetworks/ZodiacFX). Github is a
sourse code repository designed to host projects maintained using Git.

Under Debian say

```sh
sudo apt-get install git
```

### Copy ZodiacFX git repository

Change to your home directory, or some similar working directory.

```sh
git clone https://github.com/NorthboundNetworks/ZodiacFX.git
```

This create a ZodiacFX subdirectory and will copy into the
subdirectory the entire source code and history.

### Compile and link

```sh
cd ZodiacFX
cd ZodiacFX
make -j4
```

The subdirectory should already contain a Makefile.

This will compile all C files — found under src/ — into object files,
link the object files to produce ZodiacFX.elf, then transform
ZodiacFX.elf into ZodiacFX.bin.

## Use JTAG to flash the ZodiacFX with the binary image

The next task is to get the ZodiacFX.bin onto the flash on the
ZodiacFX.

There are currently two ways to do this: the
[Atmel-ICE JTAG/SWD debugger](http://northboundnetworks.com/products/zodiac-fx-hardware-debugger)
or the
[Atmel SAM-BA USB in-system programmer](http://www.atmel.com/tools/atmelsam-bain-systemprogrammer.aspx).

SAM-BA has no source code: only pre-compiled versions for Windows and
Linux on Intel x86 and AMD64 are available. There is a open source
alternative named [BOSSA](https://github.com/shumatech/BOSSA) but
BOSSA currently has no support for the SAM4 family of systems-on-chip.

The Northbound Networks manual descibes how to download a .bin file
using SAM-BA. The remainder of this section will explain how to do so
using the JTAG programmer.

### Install OpenOCD

[OpenOCD](http://openocd.org/) made large advances with version
0.9.0. Do not use an earlier version; in any case, they have no
support for the Atmel SAM4.

OpenOCD v0.9.0 can be found in Debian Jessie Backports.

```sh
echo 'deb http://ftp.debian.org/debian jessie-backports main' | sudo tee --append /etc/apt/sources.list.d/backports.list > /dev/null
sudo apt-get update
sudo apt-get --target-release jessie-backports install openocd
```

Raspbian doesn't have a backports repository. In that case download
the latest .deb source and re-build the package.  For guidance see
[Rebuilding a Debian package](http://vk5tu.livejournal.com/46855.html).

### Configure OpenOCD

OpenOCD looks for a openocd.cfg file in the current directory. A
working configuration for the Atmel-ICE JTAG programmer connected to
the Zodiac FX can be found in …/ZodiacFX/ZodiacFx/openocd.cfg.

Connecting the Atmel ICE to the Zodiac FX is straightforward. Power
down both units. The cable goes into the "SAM" port on the ICE. The
ribbon cable has pin 1 marked, this goes furthest from the "JTAG" silk
screen printing on the Zodiac FX's printed circuit board. Power up the
Ateml ICE, then power up the Zodiac FX.

More details on the configuration and use of OpenOCD can be found in
[Using Atmel-ICE JTAG/USB dongle and OpenOCD with ZodiacFX OpenFlow switch](http://vk5tu.livejournal.com/56648.html).

### Program ZodiacFX flash with binary image

Change to the directory containing openocd.cfg and ZodiacFX.bin.

To save error the openocd.cfg file defines a convenience function to
program the flash, so we use it:

```sh
openocd -f openocd.cfg -c zodiacfx_bin
```

This is called by `make jtaginstall'.

Alternatively from within the debugger `zodiacfx_write_image' is a
wrapper for `flash write_image' which gives the correct load address.

```sh
telnet localhost 4444
halt
zodiacfx_write_image ZodiacFX.bin
exit
```

Underneath this runs the OpenOCD commands

```
init
reset init
flash write_image erase ZodiacFX.bin 0x00400000 bin
# Boot from flash by setting register GPNVM1
at91sam4 gpnvm set 1
reset run
exit
```

## Using ZodiacFX

These are brief instructions for using the Zodiac FX from Linux.

### Install and configure terminal emulator

```sh
sudo apt-get install minicom
```

Create a file /etc/udev/rules.d/77-northbound-networks.rules
containing

```
# Northbound Networks
#  Zodiac FX OpenFlow switch
ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2404", ENV{ID_MM_DEVICE_IGNORE}="1", GROUP="adm", MODE="0660", SYMLINK+="ttyzodiacfx"
#  Zodiac FX OpenFlow switch after flash "erase" jumper has been run
#  The Atmel SAM4E Cortex-M4F CPU is running a bootloader waiting for software
#  download via USB and the SAM-BA tool (the CPU is Atmel part ATSAM4E8C-AU,
#  use board description "at91sam4e8-ek").
ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="6124", ENV{ID_MM_DEVICE_IGNORE}="1", GROUP="adm", MODE="0660", SYMLINK+="ttyat91sam4e8-ek"
# Atmel-ICE JTAG/SWD
ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2141", MODE="664", GROUP="plugdev"
```

Activate this udev configuration with

```sh
sudo udevadm control --reload
```


Depending upon your environment you could create a new group to
control access to the Zodiac FX command prompt. For example

```sh
sudo groupadd --system zodiacfx
```

and then set GROUP="zodiacfx" in the udev rules.  You add yourself to
the zodiacfx group with

```sh
sudo usermod --append --groups zodiacfx $USER
```

Create a file /etc/minicom/minirc.zodiacfx containing

```
pu port /dev/ttyzodiacfx
pu mhangup
pu showspeed 1
```

Plug in the USB port to the ZodiacFX. This will create a /dev/ttyACM0
device file. There will be a symbolic link /dev/ttyzodiacfx to that
device.

Start the terminal emulator.

```
minicom zodiacfx
```

Pressing Enter will bring up the Zodiac FX logo and prompt

```
Zodiac_FX#
```

Type "help" and press Enter to see what commands are available.

To exit Minicom type Crtl+A X Enter.

### Networking

There are a few pre-set IP addresses in the Zodiac FX

```
Zodiac_FX# config
Zodiac_FX(config)# show config
Configuration
 IP Address: 10.0.1.99
 Netmask: 255.255.255.0
 Gateway: 10.0.1.1
 OpenFlow Controller: 10.0.1.8
 OpenFlow Port: 6633
Zodiac_FX(config)# exit
```

If we just want to experiment with a controller on our computer then
plug the computer and Zodiac FX into the same LAN and set a secondary
address on the computer's ethernet port.

```sh
sudo ip addr add 10.0.1.8/24 label eth0:zodiacfx dev eth0
```

For more information on getting started with the Zodiac FX under Linux
see
[Getting started with Northbound Networks' Zodiac FX OpenFlow switch](http://vk5tu.livejournal.com/55803.html).

## Debugging

### Decoding the OpenFlow protocol

Decoding the OpenFlow protocol between the computer and the Zodiac FX
can be useful for exploring issues.

Wireshark is a graphical protocol analyser which is the best choice
for decoging the OpenFlow protocol. If you are consitently using port
6633 rather than the IANA-assigned port 6653 then edit the file
~/.wireshark/preferences and add

```
openflow.tcp.port: 6633
```

When a graphical interface is not available then tcpdump is a widely
available choice to capture a OpenFlow protocol packets to a
file. That file can then be transferred to a machine which can run
Wireshark.

```sh
sudo tcpdump -i eth0 -s 0 -w openflow.pcap 'tcp port 6633 or tcp port 6653 or icmp'
sudo chown $USER:$USER openflow.pcap
gzip -9 openflow.pcap
```

Tshark is a Wireshark program which can dump the protocol in
text. This is particularly useful for including a packet in bug
reports. To decode the capture file above say

```sh
tshark -V -x -2 -d tcp.port==6633,openflow -r openflow.pcap.gz
```

The manual page explains how to choose a particular frame of a capture file.

These programs can be installed with

```sh
apt-get install tcpdump wireshark tshark
```

### Using GDB



## Development

### Install Exuberant ctags

The Makefile assumes that Exuberant ctags is the tags creation
utility. Mainly because that made writing the Makefile simpler.

```sh
apt-get install exuberant-ctags
```

Say `make tags` to create a TAGS file for Emacs.

### Structure of the ZodiacFX source code

ZodiacFX/

ZodiacFX/src

ZodiacFX/src/ASF

ZodiacFX/src/lwip


### Contributing using git and GitHub

## Copyright

Copyright © Glen Turner, 2016

Licensed to you under the Creative Commons Attribution-ShareAlike 4.0
International license. For the text of the license see
<http://creativecommons.org/licenses/by-sa/4.0/legalcode>

