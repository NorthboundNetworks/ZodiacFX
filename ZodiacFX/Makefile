#!/usr/bin/make -f
# Makefile for Zodiac FX being compiled under Linux.
#
# USE
#
# To compile say
#   $ make -j4
# where "4" is the number of CPU cores available.
# Download the resulting ZodiacFX.bin to the device.
# If you need a debugging version then say
#   $ make debug
# The useful output there is ZodiacFX.elf as you can hand that
# to arm-none-eabi-gdb as the symbol table when debugging over
# the JTAG link.
# To tidy up and and return to a clean tree say
#   $ make clean
#
# PERFORMANCE
#
# Complete build on Raspberry Pi 3 model B (4*76BogoMIPS, RPi1 was 1*2BogoMIPS):
#   $ make -j4
#   real  0m13.859s
#   user  0m43.890s
#   sys   0m4.080s
#
#   $ make -j4 debug
#   real  0m25.496s
#   user  1m23.030s
#   sys   0m6.130s
#
# Time to recompile after a single-file change is 2.2s. Without the
# ZodiacFX.map, linker cross-reference and ZodiacFX.lss.gz targets
# this is reduced to 0.8s.
#
# DEVELOPMENT
#
# This file is created from screen dumps of Atmel Studio 7's
# GUI where the pathnames and compiler options are given.
# No content is from Makefiles that Atmel Studio itself
# might use. Because this is from second-hand screendumps I
# did not use Atmel Studio myself, nor agree to its license.
# If you want to report bugs against this file please retain
# this impingement-free status by explaining what should happen,
# not by including extracts from Atmel products.
#
# An unfortunate side-effect of this perhaps-too-pure cleanrooming
# is that this file follows the Unix norms rather than the conventions
# which Atmel's website suggests are needed for Atmel Studio. Thus
# this file is unlikely to work under Atmel Studio.  In the long run
# is is desriable to have the same Makefile for both Unix (ARM GCC
# under Debian, Ubuntu or Fedora) and for Windows (Atmel Studio). If
# you would like that corrected then describe the enhancements needed
# in a cleanroom-preserving way and I'll change this file.
#
# This is pretty much a brute-force Makefile. It could be made neater
# to:
#  - automatically derive dependencies. I really haven't done any
#    dependency generation for ASF or LWIP as I don't see that people
#    will mess with those files.
#  - a more structured Makefile. I won't take patches for recursive
#    Makefiles, but some sort of .include scheme is fine.
#
# "release" (the default) and "debug" are mutually exclusive targets,
# and so when we want different actions for those outcomes we use
# GNU Make's target-specific variables. See
# <http://www.gnu.org/software/make/manual/make.html#Target_002dspecific>
#
# Copyright (C) Glen Turner, 2016.
# Copyright (c) 2016 Northbound Networks.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Glen Turner <http://www.gdt.id.au/~gdt/>

# Cross-compiling using ARM Ltd port of GNU C compiler.  This is very
# obviously the same compiler used by the Atmel development environment.
# Under Debian: 
#  apt-get install gcc-arm-none-eabi binutils-arm-none-eabi 
#                  gdb-arm-none-eabi libstdc++-arm-none-eabi-newlib
ARMGCC = arm-none-eabi-
CC = $(ARMGCC)gcc
LD = $(ARMGCC)ld
OBJCOPY = $(ARMGCC)objcopy
OBJDUMP = $(ARMGCC)objdump
SIZE = $(ARMGCC)size
PERL = perl

PROJECT=ZodiacFX

# ARM/GNU Common
# All options
# This drives a heap of board support macros in the Atmel Software Framework
CPPFLAGS += -D__SAM4E8C__
# Datasheet says the Atmel SAM4E is Cortex M4
CFLAGS += -mcpu=cortex-m4
# Datasheet says Cortex M4 only supports Thumb-2 instructions
CFLAGS += -mthumb

# ARM/GNU C Compiler -- Symbols -- Defined symbols (-D)
# <armgcc.compiler.symbols.DefSymbols>
release : CPPFLAGS += -DNDEBUG
CPPFLAGS += -Dscanf=iscanf
CPPFLAGS += -DBOARD=USER_BOARD
CPPFLAGS += -DARM_MATH_CM4=true
CPPFLAGS += -Dprintf=iprintf
CPPFLAGS += -DUDD_ENABLE

# ARM/GNU C Compiler -- Directories -- Include paths (-I)
# <armgcc.compiler.directories.IncludePaths>
CPPFLAGS += -I./common/applications/user_application/user_board/config
CPPFLAGS += -I./src/config
CPPFLAGS += -I./src/ASF/thirdparty/CMSIS/Lib/GCC
CPPFLAGS += -I./src/ASF/common/utils
CPPFLAGS += -I./src
CPPFLAGS += -I./src/ASF/sam/utils/fpu
CPPFLAGS += -I./src/ASF/sam/utils
CPPFLAGS += -I./src/ASF/sam/utils/preprocessor
CPPFLAGS += -I./src/ASF/sam/utils/cmsis/sam4e/include
CPPFLAGS += -I./src/ASF/common/boards
CPPFLAGS += -I./src/ASF/sam/utils/header_files
CPPFLAGS += -I./src/ASF/common/boards/user_board
CPPFLAGS += -I./src/ASF/thirdparty/CMSIS/Include
CPPFLAGS += -I./src/ASF/sam/utils/cmsis/sam4e/source/templates
CPPFLAGS += -I./src/ASF/sam/drivers/pmc
CPPFLAGS += -I./src/ASF/common/services/clock
CPPFLAGS += -I./src/ASF/common/services/ioport
CPPFLAGS += -I./src/ASF/common/services/spi/sam_usart_spi
CPPFLAGS += -I./src/ASF/common/services/spi
CPPFLAGS += -I./src/ASF/common/services/twi
CPPFLAGS += -I./src/ASF/sam/services/flash_efc
CPPFLAGS += -I./src/ASF/sam/drivers/twi
CPPFLAGS += -I./src/ASF/sam/drivers/efc
CPPFLAGS += -I./src/ASF/sam/drivers/usart
CPPFLAGS += -I./src/ASF/sam/drivers/gmac
CPPFLAGS += -I./src/ASF/sam/drivers/matrix
CPPFLAGS += -I./src/ASF/sam/drivers/pio
CPPFLAGS += -I./src/ASF/sam/drivers/rtc
CPPFLAGS += -I./src/ASF/common/services/sleepmgr
CPPFLAGS += -I./src/ASF/common/services/usb
CPPFLAGS += -I./src/ASF/common/services/usb/class/cdc
CPPFLAGS += -I./src/ASF/common/services/usb/class/cdc/device
CPPFLAGS += -I./src/ASF/common/services/usb/udc
CPPFLAGS += -I./src/ASF/common/utils/stdio/stdio_usb
CPPFLAGS += -I./src/ASF/common/utils/membag
CPPFLAGS += -I./src/ASF/sam/drivers/udp
CPPFLAGS += -I./src/ASF/sam/drivers/tc
CPPFLAGS += -I./src/ASF/common/services/spi/sam_spi
CPPFLAGS += -I./src/ASF/sam/drivers/spi
CPPFLAGS += -I./src/ASF/sam/drivers/rstc
CPPFLAGS += -I./src/lwip/include
CPPFLAGS += -I./src/lwip
CPPFLAGS += -I./src/lwip/include/ipv4
CPPFLAGS += -I./src/ASF/sam/drivers/afec

# ARM/GNU C Compiler -- Optimization
# Optimization level
CFLAGS += -O1
# Other optimization flags
CFLAGS += -fdata-sections
# Prepare functions for garbage collection
CFLAGS += -ffunction-sections
# Allow called functions to be located anywhere in the 32-bit address space
CFLAGS += -mlong-calls

# ARM/GNU C Compiler -- Debugging
# Configuration -- Debug
debug : CFLAGS += -g3

# ARM/GNU C Compiler -- Warnings
# All warnings
CFLAGS += -Wall

# ARM/GNU C Compiler -- Miscellaneous
# Other flags
CFLAGS += -pipe -fno-strict-aliasing -Wall -Wstrict-prototypes -Wmissing-prototypes -Werror-implicit-function-declaration -Wpointer-arith -std=gnu99 -ffunction-sections -fdata-sections -Wchar-subscripts -Wcomment -Wformat=2 -Wimplicit-int -Wmain -Wparentheses -Wsequence-point -Wreturn-type -Wswitch -Wtrigraphs -Wunused -Wuninitialized -Wunknown-pragmas -Wfloat-equal -Wundef -Wshadow -Wbad-function-cast -Wwrite-strings -Wsign-compare -Waggregate-return -Wmissing-declarations -Wformat -Wmissing-format-attribute -Wno-deprecated-declarations -Wpacked -Wredundant-decls -Wnested-externs -Wlong-long -Wunreachable-code -Wcast-align --param max-inline-insns-single=500 -mfloat-abi=softfp -mfpu=fpv4-sp-d16

# ARM/GNU Linker -- General

# Limit stack size
LDFLAGS += -Wl,--defsym,__stack_size__=0x1400
# Generate map file
# This will have a .map extension
LDFLAGS += -Wl,-Map=$(addsuffix .map,$(basename $@))

# ARM/GNU Linker -- Libraries
# Libraries (-l)
# The math library and their implementation are inter-dependent, so into
# a linkage group they go.
LDFLAGS += -Wl,--start-group -larm_cortexM4lf_math_softfp -lm  -Wl,--end-group
# Library search path (-L)
LDFLAGS += -L../cmsis/linkerScripts
LDFLAGS += -L./src/ASF/thirdparty/CMSIS/Lib/GCC

# ARM/GNU Linker -- Optimization
# Garbage collect unused sections
LDFLAGS += -Wl,--gc-sections

# ARM/GNU Linker -- Memory settings
# nothing set

# ARM/GNU Linker -- Miscellaneous
# Linker flags
LDFLAGS += -Wl,--entry=Reset_Handler
LDFLAGS += -Wl,--cref
LDFLAGS += -mthumb
LDFLAGS += -T./src/ASF/sam/utils/linker_scripts/sam4e/sam4e8/gcc/flash.ld

# ARM/GNU Assembler
# All options
# ASFLAGS += -mcpu=cortex-m4 -mthumb

# ARM/GNU Preprocessing assembler -- General
CPPAS = $(ARMGCC)gcc
# Assembler flags
CPPASFLAGS = -mthumb -x assembler-with-cpp -c -mcpu=cortex-m4
CPPASFLAGS += -DARM_MATH_CM4=true -DBOARD=USER_BOARD -Dprintf=iprintf -Dscanf=iscanf -DUDD_ENABLE
CPPASFLAGS += $(CPPASINC)
# Include paths (-I)
CPPASINC += -I./common/applications/user_application/user_board/config
CPPASINC += -I./src/config
CPPASINC += -I./src/ASF/thirdparty/CMSIS/Lib/GCC
CPPASINC += -I./src/ASF/common/utils
CPPASINC += -I./src
CPPASINC += -I./src/ASF/sam/utils/fpu
CPPASINC += -I./src/ASF/sam/utils
CPPASINC += -I./src/ASF/sam/utils/preprocessor
CPPASINC += -I./src/ASF/sam/utils/cmsis/sam4e/include
CPPASINC += -I./src/ASF/common/boards
CPPASINC += -I./src/ASF/sam/utils/header_files
CPPASINC += -I./src/ASF/common/boards/user_board
CPPASINC += -I./src/ASF/thirdparty/CMSIS/Include
CPPASINC += -I./src/ASF/sam/utils/cmsis/sam4e/source/templates
CPPASINC += -I./src/ASF/sam/drivers/pmc
CPPASINC += -I./src/ASF/common/services/clock
CPPASINC += -I./src/ASF/common/services/ioport
CPPASINC += -I./src/ASF/common/services/spi/sam_usart_spi
CPPASINC += -I./src/ASF/common/services/spi
CPPASINC += -I./src/ASF/common/services/twi
CPPASINC += -I./src/ASF/sam/drivers/twi
CPPASINC += -I./src/ASF/sam/drivers/usart
CPPASINC += -I./src/ASF/sam/drivers/gmac
CPPASINC += -I./src/ASF/sam/drivers/matrix
CPPASINC += -I./src/ASF/sam/drivers/pio
CPPASINC += -I./src/ASF/sam/drivers/rtc
CPPASINC += -I./src/ASF/common/services/sleepmgr
CPPASINC += -I./src/ASF/common/services/usb
CPPASINC += -I./src/ASF/common/services/usb/class/cdc
CPPASINC += -I./src/ASF/common/services/usb/class/cdc/device
CPPASINC += -I./src/ASF/common/services/usb/udc
CPPASINC += -I./src/ASF/common/utils/stdio/stdio_usb
CPPASINC += -I./src/ASF/sam/drivers/udp
CPPASINC += -I./src/ASF/sam/drivers/tc
CPPASINC += -I./src/ASF/common/services/spi/sam_spi
CPPASINC += -I./src/ASF/sam/drivers/spi
CPPASINC += -I./src/ASF/sam/drivers/rstc
CPPASINC += -I./src/ASF/sam/drivers/afec

# ARM/GNU Archiver
ARFLAGS += -r

# Use perl for the checksum as shells have difficulties with NUL bytes.
checksum = $(PERL) -e '\
open(my $$fh, "+<:raw", "$1");\
my $$csum = do {\
  local $$/;\
  unpack("%32W*", readline($$fh));\
};\
print $$fh pack("V", $$csum) . "\x00\x00\x00\x00";\
close($$fh)'

%.bin: %.elf
	$(OBJCOPY) --output-target binary $< $@
	$(call checksum,$@)
	$(SIZE) $<

# This is I/O bound, so let's compress it to tradeoff CPU for I/O
# Not sure why we need this, but since Atmel Studio produces it,
# we do too.
%.lss.gz: %.elf
	$(OBJDUMP) --section-headers --source $< | gzip --best --no-name --rsyncable --to-stdout > $@

.PHONY: release
release: all

.PHONY: debug
debug: all

.PHONY: all
all: $(PROJECT).bin $(PROJECT).lss.gz

$(PROJECT).bin: $(PROJECT).elf

$(PROJECT).lss.gz: $(PROJECT).elf

# Use an explicit rule for the linkage, in case $(PROJECT) isn't one of the
# names of the object files. The linker rule is simply the default rule.
$(PROJECT).elf: \
 src/command.o \
 src/eeprom.o \
 src/main.o \
 src/openflow/of_helper.o \
 src/openflow/openflow_10.o \
 src/openflow/openflow_13.o \
 src/openflow/openflow.o \
 src/switch.o \
 src/http.o \
 src/flash.o \
 src/timers.o \
 src/ksz8795clx/ethernet_phy.o \
 src/ASF/common/boards/user_board/init.o \
 src/ASF/common/services/clock/sam4e/sysclk.o \
 src/ASF/common/services/sleepmgr/sam/sleepmgr.o \
 src/ASF/common/services/spi/sam_usart_spi/usart_spi.o \
 src/ASF/common/services/usb/class/cdc/device/udi_cdc.o \
 src/ASF/common/services/usb/class/cdc/device/udi_cdc_desc.o \
 src/ASF/common/services/usb/udc/udc.o \
 src/ASF/common/utils/interrupt/interrupt_sam_nvic.o \
 src/ASF/common/utils/membag/membag.o \
 src/ASF/common/utils/stdio/read.o \
 src/ASF/common/utils/stdio/stdio_usb/stdio_usb.o \
 src/ASF/common/utils/stdio/write.o \
 src/ASF/sam/services/flash_efc/flash_efc.o \
 src/ASF/sam/drivers/afec/afec.o \
 src/ASF/sam/drivers/efc/efc.o \
 src/ASF/sam/drivers/gmac/gmac_phy.o \
 src/ASF/sam/drivers/gmac/gmac_raw.o \
 src/ASF/sam/drivers/matrix/matrix.o \
 src/ASF/sam/drivers/pio/pio.o \
 src/ASF/sam/drivers/pio/pio_handler.o \
 src/ASF/sam/drivers/pmc/pmc.o \
 src/ASF/sam/drivers/pmc/sleep.o \
 src/ASF/sam/drivers/rstc/rstc.o \
 src/ASF/sam/drivers/rtc/rtc.o \
 src/ASF/sam/drivers/spi/spi.o \
 src/ASF/sam/drivers/tc/tc.o \
 src/ASF/sam/drivers/twi/twi.o \
 src/ASF/sam/drivers/udp/udp_device.o \
 src/ASF/sam/drivers/usart/usart.o \
 src/ASF/sam/utils/cmsis/sam4e/source/templates/exceptions.o \
 src/ASF/sam/utils/cmsis/sam4e/source/templates/gcc/startup_sam4e.o \
 src/ASF/sam/utils/cmsis/sam4e/source/templates/system_sam4e.o \
 src/ASF/sam/utils/syscalls/gcc/syscalls.o \
 src/lwip/api/api_lib.o \
 src/lwip/api/api_msg.o \
 src/lwip/api/err.o \
 src/lwip/api/netbuf.o \
 src/lwip/api/netdb.o \
 src/lwip/api/netifapi.o \
 src/lwip/api/sockets.o \
 src/lwip/api/tcpip.o \
 src/lwip/core/def.o \
 src/lwip/core/dhcp.o \
 src/lwip/core/dns.o \
 src/lwip/core/init.o \
 src/lwip/core/ipv4/autoip.o \
 src/lwip/core/ipv4/icmp.o \
 src/lwip/core/ipv4/igmp.o \
 src/lwip/core/ipv4/inet.o \
 src/lwip/core/ipv4/inet_chksum.o \
 src/lwip/core/ipv4/ip.o \
 src/lwip/core/ipv4/ip_addr.o \
 src/lwip/core/ipv4/ip_frag.o \
 src/lwip/core/mem.o \
 src/lwip/core/memp.o \
 src/lwip/core/netif.o \
 src/lwip/core/pbuf.o \
 src/lwip/core/raw.o \
 src/lwip/core/snmp/asn1_dec.o \
 src/lwip/core/snmp/asn1_enc.o \
 src/lwip/core/snmp/mib2.o \
 src/lwip/core/snmp/mib_structs.o \
 src/lwip/core/snmp/msg_in.o \
 src/lwip/core/snmp/msg_out.o \
 src/lwip/core/stats.o \
 src/lwip/core/sys.o \
 src/lwip/core/tcp.o \
 src/lwip/core/tcp_in.o \
 src/lwip/core/tcp_out.o \
 src/lwip/core/timers.o \
 src/lwip/core/udp.o \
 src/lwip/netif/etharp.o \
 src/lwip/netif/ethernetif.o \
 src/lwip/netif/ppp/auth.o \
 src/lwip/netif/ppp/chap.o \
 src/lwip/netif/ppp/chpms.o \
 src/lwip/netif/ppp/fsm.o \
 src/lwip/netif/ppp/ipcp.o \
 src/lwip/netif/ppp/lcp.o \
 src/lwip/netif/ppp/magic.o \
 src/lwip/netif/ppp/md5.o \
 src/lwip/netif/ppp/pap.o \
 src/lwip/netif/ppp/ppp.o \
 src/lwip/netif/ppp/ppp_oe.o \
 src/lwip/netif/ppp/randm.o \
 src/lwip/netif/ppp/vj.o \
 src/lwip/netif/slipif.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH) $^ $(LOADLIBES) $(LDLIBS) -o $@

src/command.o: src/command.c

src/command.c: \
 src/command.h \
 src/config/config_zodiac.h \
 src/config/conf_eth.h \
 src/eeprom.h \
 src/switch.h \
 src/openflow/openflow.h \
 src/openflow/of_helper.h \
 src/timers.h

src/eeprom.o: src/eeprom.c

src/eeprom.c: \
 src/eeprom.h \
 src/command.h

src/main.o: src/main.c

src/main.c: \
 src/timers.h \
 src/command.h \
 src/eeprom.h \
 src/switch.h \
 src/openflow/openflow.h \
 src/ksz8795clx/ethernet_phy.h

src/openflow/of_helper.o: src/openflow/of_helper.c

src/openflow/of_helper.c: \
 src/config/config_zodiac.h \
 src/openflow/openflow.h \
 src/openflow/of_helper.h \
 src/switch.h

src/openflow/openflow_10.o: src/openflow/openflow_10.c

src/openflow/openflow_10.c: \
 src/command.h \
 src/openflow/openflow.h \
 src/switch.h \
 src/openflow/of_helper.h

src/openflow/openflow_13.o: src/openflow/openflow_13.c

src/openflow/openflow_13.c: \
 src/command.h \
 src/openflow/openflow.h \
 src/switch.h

src/openflow/openflow.o: src/openflow/openflow.c

src/openflow/openflow.c: \
 src/openflow/openflow.h \
 src/config/config_zodiac.h \
 src/command.h \
 src/switch.h \
 src/timers.h 

src/openflow/openflow.h: \
 src/openflow_spec/openflow_spec10.h \
 src/openflow_spec/openflow_spec13.h

src/switch.o: src/switch.c

src/switch.c: \
 src/openflow/openflow.h \
 src/switch.h \
 src/config/conf_eth.h \
 src/command.h \
 src/ksz8795clx/ethernet_phy.h

src/http.c: \
 src/http.h \
 src/lwip/include/lwip/tcp.h \
 src/lwip/include/lwip/err.h \
 src/timers.h \
 src/command.h \
 src/trace.h \
 src/config/config_zodiac.h \
 src/openflow/openflow.h \
 src/eeprom.h \
 src/flash.h

src/timers.o: src/timers.c

src/timers.c: \
 src/timers.h

# ./src/config/ dependencies
src/config/lwipopts.h: src/config/conf_eth.h

# ./src/ksz8795clx/ dependencies
src/ksz8795clx/ethernet_phy.o: src/ksz8795clx/ethernet_phy.c

src/ksz8795clx/ethernet_phy.c: \
 src/ksz8795clx/ethernet_phy.h \
 src/config/conf_eth.h \
 src/switch.h \
 src/command.h

# Atmel Software Framework dependencies
src/ASF/common/boards/user_board/init.o: src/ASF/common/boards/user_board/init.c

src/ASF/common/services/clock/sam4e/sysclk.o: src/ASF/common/services/clock/sam4e/sysclk.c

src/ASF/common/services/sleepmgr/sam/sleepmgr.o: src/ASF/common/services/sleepmgr/sam/sleepmgr.c

src/ASF/common/services/spi/sam_usart_spi/usart_spi.o: src/ASF/common/services/spi/sam_usart_spi/usart_spi.c

src/ASF/common/services/usb/class/cdc/device/udi_cdc.o: src/ASF/common/services/usb/class/cdc/device/udi_cdc.c

src/ASF/common/services/usb/class/cdc/device/udi_cdc_desc.o: src/ASF/common/services/usb/class/cdc/device/udi_cdc_desc.c

src/ASF/common/services/usb/udc/udc.o: src/ASF/common/services/usb/udc/udc.c

src/ASF/common/utils/interrupt/interrupt_sam_nvic.o: src/ASF/common/utils/interrupt/interrupt_sam_nvic.c

src/ASF/common/utils/membag/membag.o: src/ASF/common/utils/membag/membag.c

src/ASF/common/utils/membag/membag.c: \
 src/ASF/common/utils/membag/membag.h \
 src/config/conf_membag.h

src/ASF/common/utils/stdio/read.o: src/ASF/common/utils/stdio/read.c

src/ASF/common/utils/stdio/stdio_usb/stdio_usb.o: src/ASF/common/utils/stdio/stdio_usb/stdio_usb.c

src/ASF/common/utils/stdio/write.o: src/ASF/common/utils/stdio/write.c

src/ASF/sam/drivers/afec/afec.o: src/ASF/sam/drivers/afec/afec.c

src/ASF/sam/drivers/gmac/gmac_phy.o: src/ASF/sam/drivers/gmac/gmac_phy.c

src/ASF/sam/drivers/gmac/gmac_raw.o: src/ASF/sam/drivers/gmac/gmac_raw.c

src/ASF/sam/drivers/matrix/matrix.o: src/ASF/sam/drivers/matrix/matrix.c

src/ASF/sam/drivers/pio/pio.o: src/ASF/sam/drivers/pio/pio.c

src/ASF/sam/drivers/pio/pio_handler.o: src/ASF/sam/drivers/pio/pio_handler.c

src/ASF/sam/drivers/pmc/pmc.o: src/ASF/sam/drivers/pmc/pmc.c

src/ASF/sam/drivers/pmc/sleep.o: src/ASF/sam/drivers/pmc/sleep.c

src/ASF/sam/drivers/rstc/rstc.o: src/ASF/sam/drivers/rstc/rstc.c

src/ASF/sam/drivers/rtc/rtc.o: src/ASF/sam/drivers/rtc/rtc.c

src/ASF/sam/drivers/spi/spi.o: src/ASF/sam/drivers/spi/spi.c

src/ASF/sam/drivers/tc/tc.o: src/ASF/sam/drivers/tc/tc.c

src/ASF/sam/drivers/twi/twi.o: src/ASF/sam/drivers/twi/twi.c

src/ASF/sam/drivers/udp/udp_device.o: src/ASF/sam/drivers/udp/udp_device.c

src/ASF/sam/drivers/usart/usart.o: src/ASF/sam/drivers/usart/usart.c

src/ASF/sam/utils/cmsis/sam4e/source/templates/exceptions.o: src/ASF/sam/utils/cmsis/sam4e/source/templates/exceptions.c

src/ASF/sam/utils/cmsis/sam4e/source/templates/gcc/startup_sam4e.o: src/ASF/sam/utils/cmsis/sam4e/source/templates/gcc/startup_sam4e.c

src/ASF/sam/utils/cmsis/sam4e/source/templates/system_sam4e.o: src/ASF/sam/utils/cmsis/sam4e/source/templates/system_sam4e.c

src/ASF/sam/utils/syscalls/gcc/syscalls.o: src/ASF/sam/utils/syscalls/gcc/syscalls.c

# Leightweight IP dependencies
src/lwip/api/api_lib.o: src/lwip/api/api_lib.c

src/lwip/api/api_msg.o: src/lwip/api/api_msg.c

src/lwip/api/err.o: src/lwip/api/err.c

src/lwip/api/netbuf.o: src/lwip/api/netbuf.c

src/lwip/api/netdb.o: src/lwip/api/netdb.c

src/lwip/api/netifapi.o: src/lwip/api/netifapi.c

src/lwip/api/sockets.o: src/lwip/api/sockets.c

src/lwip/api/tcpip.o: src/lwip/api/tcpip.c

src/lwip/core/def.o: src/lwip/core/def.c

src/lwip/core/dhcp.o: src/lwip/core/dhcp.c

src/lwip/core/dns.o: src/lwip/core/dns.c

src/lwip/core/init.o: src/lwip/core/init.c

src/lwip/core/ipv4/autoip.o: src/lwip/core/ipv4/autoip.c

src/lwip/core/ipv4/icmp.o: src/lwip/core/ipv4/icmp.c

src/lwip/core/ipv4/igmp.o: src/lwip/core/ipv4/igmp.c

src/lwip/core/ipv4/inet.o: src/lwip/core/ipv4/inet.c

src/lwip/core/ipv4/inet_chksum.o: src/lwip/core/ipv4/inet_chksum.c

src/lwip/core/ipv4/ip.o: src/lwip/core/ipv4/ip.c

src/lwip/core/ipv4/ip_addr.o: src/lwip/core/ipv4/ip_addr.c

src/lwip/core/ipv4/ip_frag.o: src/lwip/core/ipv4/ip_frag.c

src/lwip/core/mem.o: src/lwip/core/mem.c

src/lwip/core/memp.o: src/lwip/core/memp.c

src/lwip/core/netif.o: src/lwip/core/netif.c

src/lwip/core/pbuf.o: src/lwip/core/pbuf.c

src/lwip/core/raw.o: src/lwip/core/raw.c

src/lwip/core/snmp/asn1_dec.o: src/lwip/core/snmp/asn1_dec.c

src/lwip/core/snmp/asn1_enc.o: src/lwip/core/snmp/asn1_enc.c

src/lwip/core/snmp/mib2.o: src/lwip/core/snmp/mib2.c

src/lwip/core/snmp/mib_structs.o: src/lwip/core/snmp/mib_structs.c

src/lwip/core/snmp/msg_in.o: src/lwip/core/snmp/msg_in.c

src/lwip/core/snmp/msg_out.o: src/lwip/core/snmp/msg_out.c

src/lwip/core/stats.o: src/lwip/core/stats.c

src/lwip/core/sys.o: src/lwip/core/sys.c

src/lwip/core/tcp.o: src/lwip/core/tcp.c

src/lwip/core/tcp_in.o: src/lwip/core/tcp_in.c

src/lwip/core/tcp_out.o: src/lwip/core/tcp_out.c

src/lwip/core/timers.o: src/lwip/core/timers.c

src/lwip/core/udp.o: src/lwip/core/udp.c

src/lwip/netif/etharp.o: src/lwip/netif/etharp.c

src/lwip/netif/ethernetif.o: src/lwip/netif/ethernetif.c

src/lwip/netif/ppp/auth.o: src/lwip/netif/ppp/auth.c

src/lwip/netif/ppp/chap.o: src/lwip/netif/ppp/chap.c

src/lwip/netif/ppp/chpms.o: src/lwip/netif/ppp/chpms.c

src/lwip/netif/ppp/fsm.o: src/lwip/netif/ppp/fsm.c

src/lwip/netif/ppp/ipcp.o: src/lwip/netif/ppp/ipcp.c

src/lwip/netif/ppp/lcp.o: src/lwip/netif/ppp/lcp.c

src/lwip/netif/ppp/magic.o: src/lwip/netif/ppp/magic.c

src/lwip/netif/ppp/md5.o: src/lwip/netif/ppp/md5.c

src/lwip/netif/ppp/pap.o: src/lwip/netif/ppp/pap.c

src/lwip/netif/ppp/ppp.o: src/lwip/netif/ppp/ppp.c

src/lwip/netif/ppp/ppp_oe.o: src/lwip/netif/ppp/ppp_oe.c

src/lwip/netif/ppp/randm.o: src/lwip/netif/ppp/randm.c

src/lwip/netif/ppp/vj.o: src/lwip/netif/ppp/vj.c

src/lwip/netif/slipif.o: src/lwip/netif/slipif.c

# If you foolishly use something other than Exuberant CTags then
# this will need major work.
# If you use vi instead then use $(CTAGS) below.
CTAGS=ctags-exuberant
ETAGS=ctags-exuberant -e
.PHONY: tags
tags:
	$(ETAGS) --recurse

.PHONY: clean
clean:
	$(RM) $(PROJECT).bin
	$(RM) $(PROJECT).lss.gz
	$(RM) $(PROJECT).elf
	$(RM) $(PROJECT).map
	$(RM) src/command.o
	$(RM) src/eeprom.o
	$(RM) src/main.o
	$(RM) src/openflow/of_helper.o
	$(RM) src/openflow/openflow_10.o
	$(RM) src/openflow/openflow_13.o
	$(RM) src/openflow/openflow.o
	$(RM) src/switch.o
	$(RM) src/timers.o
	$(RM) src/ASF/common/boards/user_board/init.o
	$(RM) src/ASF/common/services/clock/sam4e/sysclk.o
	$(RM) src/ASF/common/services/sleepmgr/sam/sleepmgr.o
	$(RM) src/ASF/common/services/spi/sam_usart_spi/usart_spi.o
	$(RM) src/ASF/common/services/usb/class/cdc/device/udi_cdc.o
	$(RM) src/ASF/common/services/usb/class/cdc/device/udi_cdc_desc.o
	$(RM) src/ASF/common/services/usb/udc/udc.o
	$(RM) src/ASF/common/utils/interrupt/interrupt_sam_nvic.o
	$(RM) src/ASF/common/utils/stdio/read.o
	$(RM) src/ASF/common/utils/stdio/stdio_usb/stdio_usb.o
	$(RM) src/ASF/common/utils/stdio/write.o
	$(RM) src/ASF/common/utils/membag/membag.o
	$(RM) src/ASF/sam/drivers/afec/afec.o
	$(RM) src/ASF/sam/drivers/gmac/gmac_phy.o
	$(RM) src/ASF/sam/drivers/gmac/gmac_raw.o
	$(RM) src/ASF/sam/drivers/matrix/matrix.o
	$(RM) src/ASF/sam/drivers/pio/pio.o
	$(RM) src/ASF/sam/drivers/pio/pio_handler.o
	$(RM) src/ASF/sam/drivers/pmc/pmc.o
	$(RM) src/ASF/sam/drivers/pmc/sleep.o
	$(RM) src/ASF/sam/drivers/rstc/rstc.o
	$(RM) src/ASF/sam/drivers/rtc/rtc.o
	$(RM) src/ASF/sam/drivers/spi/spi.o
	$(RM) src/ASF/sam/drivers/tc/tc.o
	$(RM) src/ASF/sam/drivers/twi/twi.o
	$(RM) src/ASF/sam/drivers/udp/udp_device.o
	$(RM) src/ASF/sam/drivers/usart/usart.o
	$(RM) src/ASF/sam/utils/cmsis/sam4e/source/templates/exceptions.o
	$(RM) src/ASF/sam/utils/cmsis/sam4e/source/templates/gcc/startup_sam4e.o
	$(RM) src/ASF/sam/utils/cmsis/sam4e/source/templates/system_sam4e.o
	$(RM) src/ASF/sam/utils/syscalls/gcc/syscalls.o
	$(RM) src/lwip/api/api_lib.o
	$(RM) src/lwip/api/api_msg.o
	$(RM) src/lwip/api/err.o
	$(RM) src/lwip/api/netbuf.o
	$(RM) src/lwip/api/netdb.o
	$(RM) src/lwip/api/netifapi.o
	$(RM) src/lwip/api/sockets.o
	$(RM) src/lwip/api/tcpip.o
	$(RM) src/lwip/core/def.o
	$(RM) src/lwip/core/dhcp.o
	$(RM) src/lwip/core/dns.o
	$(RM) src/lwip/core/init.o
	$(RM) src/lwip/core/ipv4/autoip.o
	$(RM) src/lwip/core/ipv4/icmp.o
	$(RM) src/lwip/core/ipv4/igmp.o
	$(RM) src/lwip/core/ipv4/inet.o
	$(RM) src/lwip/core/ipv4/inet_chksum.o
	$(RM) src/lwip/core/ipv4/ip.o
	$(RM) src/lwip/core/ipv4/ip_addr.o
	$(RM) src/lwip/core/ipv4/ip_frag.o
	$(RM) src/lwip/core/mem.o
	$(RM) src/lwip/core/memp.o
	$(RM) src/lwip/core/netif.o
	$(RM) src/lwip/core/pbuf.o
	$(RM) src/lwip/core/raw.o
	$(RM) src/lwip/core/snmp/asn1_dec.o
	$(RM) src/lwip/core/snmp/asn1_enc.o
	$(RM) src/lwip/core/snmp/mib2.o
	$(RM) src/lwip/core/snmp/mib_structs.o
	$(RM) src/lwip/core/snmp/msg_in.o
	$(RM) src/lwip/core/snmp/msg_out.o
	$(RM) src/lwip/core/stats.o
	$(RM) src/lwip/core/sys.o
	$(RM) src/lwip/core/tcp.o
	$(RM) src/lwip/core/tcp_in.o
	$(RM) src/lwip/core/tcp_out.o
	$(RM) src/lwip/core/timers.o
	$(RM) src/lwip/core/udp.o
	$(RM) src/lwip/netif/etharp.o
	$(RM) src/lwip/netif/ethernetif.o
	$(RM) src/lwip/netif/ppp/auth.o
	$(RM) src/lwip/netif/ppp/chap.o
	$(RM) src/lwip/netif/ppp/chpms.o
	$(RM) src/lwip/netif/ppp/fsm.o
	$(RM) src/lwip/netif/ppp/ipcp.o
	$(RM) src/lwip/netif/ppp/lcp.o
	$(RM) src/lwip/netif/ppp/magic.o
	$(RM) src/lwip/netif/ppp/md5.o
	$(RM) src/lwip/netif/ppp/pap.o
	$(RM) src/lwip/netif/ppp/ppp.o
	$(RM) src/lwip/netif/ppp/ppp_oe.o
	$(RM) src/lwip/netif/ppp/randm.o
	$(RM) src/lwip/netif/ppp/vj.o
	$(RM) src/lwip/netif/slipif.o
	$(RM) tags
	$(RM) TAGS

OPENOCD = openocd
.PHONY: jtaginstall
jtaginstall: $(PROJECT).bin
	$(OPENOCD) --file openocd.cfg --command "zodiacfx_bin_name $<"

BOSSA = bossa
.PHONY: bossainstall
bossainstall: $(PROJECT).bin
	$(BOSSA) --write --boot=1 --port ttyat91sam4e8-ek $<

# EOF
