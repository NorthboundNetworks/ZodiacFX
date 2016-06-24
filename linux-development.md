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
transferrable to other Linux distributions which have GNU-inspired
user programs.

## Building the binary image

### Install ARM Ltd's port of GNU Compiler Collection

ARM Ltd have a variant of the GNU Compiler Collection's C and C++
compiler for cross-compiling to ARM embedded systems. They maintain
this variant in the Ubuntu Personal Package Archive
‘team-gcc-arm-embedded’. Other Linux distributions typically pick up
the compiler's source code from that PPA.

Under Debian Jessie say

```sh
sudo apt-get install binutils-arm-none-eabi gcc-arm-none-eabi gdb-arm-none-eabi  libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib
```

A future version of Debian might change these packages' names from
‘…-arm-none-eabi’ to  to track the change of name in
ARM Ltd's Ubuntu PPA.

The version in Debian Testing more closely follows the releases in
Ubuntu, making installing ‘gcc-arm-none-eabi’ from Testing the first
recourse upon a compiler bug.

### Install GNU make

Make is a program for building binaries from source code projects.

Under Debian say

```sh
sudo apt-get install make
```

A special embedded version of make is not needed, as make runs
entirely on the computer, not on the Zodiac FX's system-on-chip.

### Install git

Git is a program for source code configuration control. The Zodiac FX
source code can be found on
[GitHub](https://github.com/NorthboundNetworks/ZodiacFX). GitHub is a
sourse code repository designed to host projects maintained using Git.

Under Debian say

```sh
sudo apt-get install git
```

### Copy ZodiacFX git repository

Change to your home directory, or some similar working directory.

```sh
git clone https://github.com/NorthboundNetworks/ZodiacFX.git
git remote add upstream https://github.com/NorthboundNetworks/ZodiacFX.git
```

This create a ZodiacFX subdirectory and will copy into the
subdirectory the entire source code and history.

We set the `upstream` remote name to note the canonical location of
Zodiac FX's source code.

### Compile and link

```sh
cd ZodiacFX
cd ZodiacFX
make -j4
```

The subdirectory should already contain a file named `Makefile`.

This will compile all the project's C files — found under src/ — into
object files, link the object files to produce ZodiacFX.elf, then
transform ZodiacFX.elf into the flashable image ZodiacFX.bin.

The `-j` parameter is the number of concurrent processes supervised by
make. Set it to the number of CPU cores available. In this example the
Raspberry Pi 3 has four cores.

## Use JTAG to flash the ZodiacFX with the binary image

The next task is to get the image in the file ZodiacFX.bin onto the
flash on the Zodiac FX.

There are currently two ways to do this: the
[Atmel-ICE JTAG/SWD debugger](http://northboundnetworks.com/products/zodiac-fx-hardware-debugger)
a hardware device or the
[Atmel SAM-BA USB in-system programmer](http://www.atmel.com/tools/atmelsam-bain-systemprogrammer.aspx)
software program.

SAM-BA has no source code: only pre-compiled versions for Windows and
Linux on Intel x86 and AMD64 are available. There is a open source
alternative named [BOSSA](https://github.com/shumatech/BOSSA) but
BOSSA currently has no support for the SAM4 family of systems-on-chip.

The Northbound Networks manual descibes how to download a .bin file
using SAM-BA. The remainder of this section will explain how to do so
using a JTAG programmer.

### Install OpenOCD

[OpenOCD](http://openocd.org/) made large advances with version
0.9.0. Do not use an earlier version; in any case, they have no
support for the Atmel SAM4.

OpenOCD v0.9.0 can be found in Debian Jessie's Backports
repository. Install OpenOCD from there with:

```sh
echo 'deb http://ftp.debian.org/debian jessie-backports main' | sudo tee --append /etc/apt/sources.list.d/backports.list > /dev/null
sudo apt-get update
sudo apt-get --target-release jessie-backports install openocd
```

The Raspberry Pi's ‘Raspbian’ port of Debian doesn't have a Backports
repository. In that case download the latest .deb source and re-build
the package.  For guidance see
[Rebuilding a Debian package](http://vk5tu.livejournal.com/46855.html).

### Configure OpenOCD

OpenOCD looks for a configuration file named openocd.cfg in the
current directory. A working configuration for the Atmel-ICE JTAG
programmer connected to the Zodiac FX can be found in
…/ZodiacFX/ZodiacFx/openocd.cfg.

Connecting the Atmel ICE to the Zodiac FX is straightforward. Power
down both units. The cable goes into the ‘SAM’ port on the ICE. The
ribbon cable has pin 1 coloured red, this goes furthest from the
‘JTAG’ silk screen printing on the Zodiac FX's printed circuit
board. Power up the Atmel-ICE, then power up the Zodiac FX.

If you have multiple JTAG units then place the serial number of this
JTAG unit into …/ZodiacFX/ZodiacFx/openocd.secret. For example:

```
cmsis_dap_serial J12300012345
```

The file openocd.secret will be ignored by git, and so the device's
serial number (needed for warranty service) won't be uploaded to
GitHub and become widely known. You can find the serial number of the
unit by plugging the unit's USB cable into the computer and then
looking at the output of `dmesg`.

More details on the configuration and use of OpenOCD can be found in
[Using Atmel-ICE JTAG/USB dongle and OpenOCD with ZodiacFX OpenFlow switch](http://vk5tu.livejournal.com/56648.html).

### Program ZodiacFX flash with binary image

Change to the directory containing openocd.cfg and ZodiacFX.bin.

To save error the openocd.cfg file defines a convenience function to
program the flash:

```sh
openocd -f openocd.cfg -c zodiacfx_bin
```

If this fails with an access permission then check the group ownership
set in /etc/udev/rules.d/77-northbound-networks.rules.

For further convenience, `make jtaginstall' will compile, link and
program the ZodiacFX's flash.

If you are in the OpenOCD command line for other reasons then
`zodiacfx_write_image` is a wrapper for `flash write_image` which
gives the correct load address:

```
telnet localhost 4444
halt
zodiacfx_write_image ZodiacFX.bin
exit
```

Underneath the hood, all of these alternatives run the same OpenOCD
commands:

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

### Configure udev

Create a group for Zodiac FX users:

```sh
sudo groupadd --system zodiacfx
```

Create a group for Zodiac FX development. Such a group is
traditionally named ‘eng’, short for ‘engineering’:

```sh
sudo groupadd --system eng
```

Add yourself to these groups:

```sh
sudo usermod --append --groups zodiacfx,eng $USER
```

Log out and log back in again.

Create a file /etc/udev/rules.d/77-northbound-networks.rules
containing:

```
# Northbound Networks
#  Zodiac FX OpenFlow switch
ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2404", ENV{ID_MM_DEVICE_IGNORE}="1", GROUP="zodiacfx", MODE="0660", SYMLINK+="ttyzodiacfx"
#  Zodiac FX OpenFlow switch after flash "erase" jumper has been run
#  The Atmel SAM4E Cortex-M4F CPU is running a bootloader waiting for software
#  download via USB and the SAM-BA tool (the CPU is Atmel part ATSAM4E8C-AU,
#  use board description "at91sam4e8-ek").
ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="6124", ENV{ID_MM_DEVICE_IGNORE}="1", GROUP="eng", MODE="0660", SYMLINK+="ttyat91sam4e8-ek"
# Atmel-ICE JTAG/SWD
ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2141", MODE="664", GROUP="eng"
```

Activate this udev configuration with

```sh
sudo udevadm control --reload
```

### Install and configure terminal emulator

```sh
sudo apt-get install minicom
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

Type `help` and press Enter to see what commands are available.

To exit Minicom type Ctrl+A X Enter.

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

## Development

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
gzip --best openflow.pcap
scp openflow.pcap.gz eg.example.com:
```

True Unix masochists can combine all of the above into one pipe from
hell. As well as the intellectual exercise, that can be useful if the
capturing machine lacks disk space.

Tshark is a Wireshark program which can dump the protocol in
text. This is particularly useful for including a packet in bug
reports. To decode the capture file above say:

```sh
tshark -V -x -2 -d tcp.port==6633,openflow -r openflow.pcap.gz
```

The manual page explains how to choose a particular frame of a capture
file.

These programs can be installed with:

```sh
sudo apt-get install tcpdump wireshark tshark
sudo usermod --append --groups wireshark $USER
```

### Structure of the Zodiac FX source code

* `ZodiacFX/ZodiacFX/` contains the Makefile and openocd.conf

* `ZodiacFX/ZodiacFX/src` contains the Zodiac FX OpenFlow source code.

* `ZodiacFX/ZodiacFX/src/config` contains the header files giving
  configuration parameters, mostly for the ASF and LWIP source. A
  notable exception is `config_zodiac.h` which gives parameters for
  the Zodiac FX's bespoke source code.

* `ZodiacFX/ZodiacFX/ksz8795clx` contains the driver for the ethernet
  switch chip.

* `ZodiacFX/ZodiacFX/src/ASF` contains the Atmel Software Foundation
   code. The entirety of the ASF code is not here, only that selected for
   use in this project. You should not need to alter this code.

* `ZodiacFX/ZodiacFX/src/lwip` contains the Lightweight IP source
  code. You should not need to alter this code.

* `ZodiacFX/ZodiacFX/src/openflow_spec` contains header files from the
  OpenFlow specifications. You should not need to alter this code.

### Install Exuberant ctags

The Makefile assumes that Exuberant ctags is the tags creation
utility. Mainly because that made writing the Makefile simpler.

```sh
apt-get install exuberant-ctags
```

Say `make tags` to create a TAGS file for Emacs.

### Compiling with debugging options

To compile for debugging say

```sh
make clean
make -j4 debug
```

ZodiacFX.bin contains an image file for writing to flash, ZodiacFX.elf
contains debugging symbols for use by GDB.

Note that compiling for release sets the C processor variable `NDEBUG`
and compiling for debugging does not set that variable.  Mark code for
debugging with:

```cpp
#ifndef NDEBUG
  printf("Hello world\n");
#endif
```

It is convention that the code has the same broad behaviour whatever
the setting of `NDEBUG`.

### Using GNU Debugger with OpenOCD and JTAG

Remember to write the ZodiacFX.bin matching the ZodiacFX.elf to the
Zodiac FX's flash memory.

Start OpenOCD from the directory containing openocd.cfg:

```sh
openocd
```

Start the GNU debugger from that same directory:

```sh
arm-none-eabi-gdb --symbols=ZodiacFX.elf --eval-command="target extended-remote localhost:3333"
```

Set break points or inspect memory or do whatever gdb tasks you had in
mind and then say `continue`.

The usual front-ends to the GNU Debugger work, however you may need to
alter the front-end's configuration to use `arm-none-eabi-gdb` rather
than to use `gdb`.

The shipped openocd.cfg contains a handler to automatically halt the
ZodiacFX when GDB attaches to OpenOCD. If you use a different
openocd.cfg then you should halt the CPU by hand before running GDB:

```sh
telnet localhost 4444
halt
exit
```

### Contributing using git and GitHub

Create an account on [GitHub](http://github.com/).

In your web browser log into GitHub, open the
[Northbound Networks ZodiacFX repository](https://github.com/NorthboundNetworks/ZodiacFX),
press the ‘Fork’ button to create a copy of the ZodiacFX repository in
your account.

Alter git's pointer to the ‘origin’ repository of the ZodiacFX files
on your disk. Replace `$USER` below with your GitHub account name.

```sh
# Current origin should be https://github.com/NorthboundNetworks/ZodiacFX
git remote -v
# Alter the origin to the fork in our Github account
git remote remove origin
git remote add origin https://github.com/$USER/ZodiacFX.git
```

We now have three Git repositories of the source code:

* the repository on disk

* the repository in our GitHub account. The repository on disk knows
  this as its ‘origin’.

* the repository in Northbound Networks' GitHub account. The repository
  on disk knows this as its ‘upstream’.

Here are some typical workflows.

#### Finished editing files, commit to repository on disk

```
git commit
```

Take care with the commit comments, they will stay with the code
whereever it goes.

There are two parts to a commit comment: a short pithy one line
summary; and following a blank line, a long discursive
description. Both are valuable and should take some thought.

#### Send the repository on disk to GitHub

```
git push origin master
```

#### Synchronise repository on disk with latest from Northbound Networks

You will need to have no uncommitted changes on disk.

To keep our changes whilst getting the latest from Northbound
Network's repository:

```
git fetch upstream
git checkout master
git merge upstream/master
```

Once the merge is successful then you can push to your own GitHub
repository as normal with `git push origin master`.

#### Ask Northbound Networks to add your code to their repository

Ensure any new source code files have a copyright notice and the GPL3+
license text.

In your web browser log into your GitHub account. Then go to
[Northbound Networks ZodiacFX repository](https://github.com/NorthboundNetworks/ZodiacFX).
Press the tab labelled ‘Pull requests’. Press the button marked ‘New
pull request’. Click on the link ‘Compare across forks’. Select the
‘head fork’ dropdown and click on your repository. After a few seconds
this will display the changes. Press the button marked ‘Create pull
request’, check the summary, and press the button marked ‘Create pull
request’ once again.

### Memory map

Without some notion of the memory map it can seem as if embedded
applications are overflowing with magic addresses.

The memory maps of peripheral device registers are complex, the result
of having a wide range of models but wanting the same peripheral to
appear at the same addresses throughout the range. For any one model —
with a only a selected subset of the peripherals — the memory map of
the I/O registers is essentially random.

These tables summarise the memory map of the ATSAM4E8C used in the
Zodiac FX. For a complete reference see Chapter 7 of *SAM4E
series. SMART ARM-based Flash MCU. Datasheet*
([PDF](http://www.atmel.com/Images/Atmel-11157-32-bit-Cortex-M4-Microcontroller-SAM4E16-SAM4E8_Datasheet.pdf)).

The system-on-chip at the heart of the Zodiac FX is Atmel part
ATSAM4E8C-AU. This SAM4E8C belongs to the SAM4E range, in the SAM4
family. The SAM4E CPU uses ARM Ltd's ‘Cortex-M4’ design. The ATSAM4E8C
system-on-chip contains 512KB flash and 128KB of static RAM. It has a
fast ethernet controller which uses Synopsys DesignWare's ‘GMAC’
design.

This is the memory map, shorn of reserved areas:

| Lowest address | Highest address | Occupied by                 |
|----------------|-----------------|-----------------------------|
|      0000 0000 |       003f ffff | Boot memory                 |
|      0040 0000 |       41ff ffff | Internal flash (512KB)      |
|      0080 0000 |       00bf ffff | Internal ROM                |
|      2000 0000 |       2007 ffff | Internal static RAM (128KB) |
|      4000 0000 |       400c 7fff | Perpherals                  |
|      400e 0000 |       400e 1900 | System controller           |
|      e000 0000 |       ffff ffff | System                      |

The internal ROM contains the SAM-BA SAM Boot Assistant (and flash
updater) starting at address 0000 0000. It also contains
In-Application Programming (IAP) routines, and Fast Flash Programming
Interface (FFPI) for programs to implement their on flash updating.

For easy reference, the base addresses of sets of registers used by
the subsystems are shown:

| Lowest address | Occupied by                                                      |
|----------------|------------------------------------------------------------------|
|      4000 0000 | `PWM` pulse width modulation controller for stepper motors       |
|      4000 4000 | `AES` encryptor                                                  |
|      4001 0000 | `CAN0` car area network                                          |
|      4001 4000 | `CAN1` car area network                                          |
|      4003 4000 | `GMAC` ethernet controller                                       |
|      4006 0000 | `SMC` static memory controller (system)                          |
|      4006 0600 | `UART1` universal asychronous receiver/transmitter (system)      |
|      4008 0000 | `HSMCI` multimedia card                                          |
|      4008 4000 | `UDP` UDP device port                                            |
|      4008 8000 | `SPI` serial peripheral interface                                |
|      4009 0000 | `TC0` timer/counter                                              |
|      4009 0040 | `TC1` timer/counter                                              |
|      4009 0080 | `TC2` timer/counter                                              |
|      4009 4000 | `TC3` timer/counter                                              |
|      4009 4040 | `TC4` timer/counter                                              |
|      4009 4080 | `TC5` timer/counter                                              |
|      4009 8000 | `TC6` timer/counter                                              |
|      4009 8040 | `TC7` timer/counter                                              |
|      4009 8080 | `TC8` timer/counter                                              |
|      400a 0000 | `USART0` universal synchronous/asynchronous receiver/transmitter |
|      400a 4000 | `USART1` universal synchronous/asynchronous receiver/transmitter |
|      400a 8000 | `TW0` two-wire interface                                         |
|      400a c000 | `TW1` two-wire interface                                         |
|      400b 0000 | `AFEC0` analog front-end controller                              |
|      400b 4000 | `AFEC1` analog front-end controller                              |
|      400b 8000 | `DACC` digital-to-analog converter controller                    |
|      400b c000 | `ACC` analog comparator controller                               |
|      400c 0000 | `DMAC` DMA controller (system)                                   |
|      400c 4000 | `CMCC` Cortex-M cache controller (system)                        |
|      400e 0200 | `MATRIX` bus matrix (system)                                     |
|      400e 0400 | `PMC` power management controller (system)                       |
|      400e 0600 | `UART0` universal asychronous receiver/transmitter  (system)     |
|      400e 0740 | `CHIPID` chip identifier (system)                                |
|      400e 0a00 | `EEFC` enhanced embedded flash controller (system)               |
|      400e 0e00 | `PIOA` parallel I/O controller                                   |
|      400e 1000 | `PIOB` parallel I/O controller                                   |
|      400e 1200 | `PIOC` parallel I/O controller                                   |
|      400e 1400 | `PIOD` parallel I/O controller                                   |
|      400e 1600 | `PIOE` parallel I/O controller                                   |
|      400e 1800 | `RSTC` reset controller (system)                                 |
|      400e 1810 | `SUPC` [power] supply controller (system)                        |
|      400e 1830 | `RTT` real-time timer (system)                                   |
|      400e 1850 | `WDT` watchdog timer (system)                                    |
|      400e 1860 | `RTC` real-time clock (system)                                   |
|      400e 1890 | `GPBR` general purpose backup registers (system)                 |
|      400e 1900 | `RSWDT` reinforced safety watchdog timer (system)                |

### Boot sequence and ROM monitor

When a Cortex-M CPU boots it examines a vector table at address
0000 0000. This contains the initial Stack Pointer (which
conventionally points to the highest address in RAM) and a Reset
Vector, which should point to a program in ROM to run. That program
can create a new Vector Table and then write the new table's address
to the Vector Table Offset Register.

The SAM4 contains a bit register `GPNVM1`. If thus is set then the
flash memory is mapped at 0000 0000, as well as remaining mapped at
0040 0000. If `GPNVM1` is not set then ROM is mapped at 0000 0000 as
well as remaining mapped at 0080 0000.

The idea is that GPNVM1 is set after flash is successfully
programmed. GPNVM1 is automatically unset whenever a flash erase
occurs.

The double-mapping is neat: the vector table starts at 0000 0000 but
the vector contents point into ROM or flash addresses without any need
to alter the typical linkage.

A SAM4 with the typical factory ROM contains a small monitor called
SAM-BA. This can be accessed from UART0 (which is not connected on the
Zodiac FX) or from the USB port. The monitor can read and write bytes
to RAM, change the Program Counter, and transfer data using the Xmodem
serial protocol. This is sufficient capablity to write a file to
flash. The SAM-BA utility for Windows and Linux is a client to the
SAM-BA ROM monitor which automates this capability.

The Zodiac FX's ‘Erase’ jumper is connected to the `ERASE` pin of the
SAM4. When this is asserted the SAM4 will erase all flash (setting it
to zero) and clear all the `GPNVM` bits to zero. After removing the
jumper and reseting, the Zodiac FX will start from ROM, run the SAM-BA
monitor and be in a condition for a new flash image to be downloaded.

When the Zodiac FX does boot from flash `startup_sam4e.c` contains the
establishment of the vector table: the C structure `exception_table`
is placed in linker section `.vectors` and the `flash.ld` linkage
script ensures that `.vectors` is the first section. The Reset Vector
in `exception_table` points to the function `Reset_Handler()`, so this
the first code run when the Zodiac FX starts. After initialising the
system, relocating relocatable sections, zeroising zeroed sections,
and setting a new Vector Table, it initialises the C library by
calling `__libc_init_array()` and then calls the `main()` routine of
the Zodiac FX code.

Zodiac FX's `main()` function calls the `…_init()` functions of the
used Atmel Software Framework components. Some of these initialise
board components, others prepare software data structures. The saved
configuration is loaded, and the addresses from that used to
initialise the Lightweight IP library, start networking and configure
interfaces. The main loop then starts: one thread processing the
command line interface and another thread processing OpenFlow
commands.

## Copyright

Copyright © Glen Turner, 2016

Licensed to you under the Creative Commons Attribution-ShareAlike 4.0
International license. For the text of the license see
<http://creativecommons.org/licenses/by-sa/4.0/legalcode>
