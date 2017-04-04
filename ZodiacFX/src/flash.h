/**
 * @file
 * flash.h
 *
 * This file contains the function declarations for the Flashing functions
 *
 */

/*
 * This file is part of the Zodiac FX firmware.
 * Copyright (c) 2016 Google Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Paul Zanna <paul@northboundnetworks.com>
 *		 & Kristopher Chen <Kristopher@northboundnetworks.com>
 *
 */


#ifndef FLASH_H_
#define FLASH_H_

void get_serial(uint32_t *uid_buf);
void cli_update(void);
int flash_write_page(uint8_t *flash_page);
int firmware_update_init(void);
__no_inline RAMFUNC void firmware_update(void);
int xmodem_xfer(void);
void xmodem_clear_padding(uint8_t *buff);

int verification_check(void);

struct verification_data
{
	uint32_t calculated;	// Last 4 bytes from summed data
	uint32_t found;			// 4 bytes at the end of uploaded firmware
};

#define X_EOT 0x04
#define X_ACK 0x06
#define X_NAK 0x15

#define FLASH_BUFFER 0x448000
#define FLASH_BUFFER_END 0x480000

#define NN_VERIFICATION_LEN	8

#endif /* FLASH_H_ */