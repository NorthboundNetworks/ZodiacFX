/**
 * @file
 * flash.c
 *
 * This file contains the function the Flashing functions
 *
 */

/*
 * This file is part of the Zodiac FX firmware.
 * Copyright (c) 2016 Northbound Networks.
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
 * Authors: Paul Zanna <paul@northboundnetworks.com>
 *		  & Kristopher Chen <Kristopher@northboundnetworks.com>
 *
 */

#include <asf.h>
#include <inttypes.h>
#include <string.h>
#include "config_zodiac.h"
#include "openflow/openflow.h"

// Global variables
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];

// Internal Functions
void xmodem_xfer(void);
void xmodem_clear_padding(uint8_t *buff);
void flash_write_page(uint8_t *flash_page);


/*
*	Get the unique serial number from the CPU
*
*/
void get_serial(uint32_t *uid_buf)
{
	uint32_t uid_ok = flash_read_unique_id(uid_buf, 4);
	return;
}

/*
*	Firmware update function
*
*/
void firmware_update(void)
{
	xmodem_xfer();	// Receive new firmware image vie XModem
	// TODO: Update main firmware image

}

/*
*	XModem transfer
*
*/
xmodem_xfer(void)
{
	char ch;
	int timeout_clock = 0;
	int byte_count = 1;
	int block_count = 1;
	uint8_t xmodem_crc = 0;
	
	while(1)
	{
		while(udi_cdc_is_rx_ready()){
			ch = udi_cdc_getc();
			timeout_clock = 0;	// reset timeout clock
			
			// Check for <EOT>
			if (block_count == 1 && ch == 4)	// Note: block_count is cleared to 0 and incremented at the last block
			{
				printf("%c",6);	// Send final <ACK>
				xmodem_clear_padding(&shared_buffer); // strip the 0x1A fill bytes from the end of the last block
				flash_write_page(&shared_buffer);	// TODO: Testing a image < 512 bytes, will change this to allow the full image size
			}
			
			if (block_count == 132)	// End of block?
			{
				if (xmodem_crc == ch)	// Check CRC
				{
					printf("%c",6);		// If the CRC is OK then send a <ACK>
					// TODO: Write a page to flash is 4 blocks received
					block_count = 0;	// Start a new block
					} else {
					printf("%c",21);	// If the CRC is incorrect then send a <NACK>
					block_count = 0;	// Start a new block
					byte_count -= 128;
				}
				xmodem_crc = 0;		// Reset CRC
			}

			// Don't store the first 3 bytes <SOH>, <###>, <255-###>
			if (block_count > 3)
			{
				shared_buffer[byte_count-1] = ch;	// Testing only, need to find a place to store firmware image
				byte_count++;
				xmodem_crc += ch;
			}
			block_count++;
		}
		timeout_clock++;
		if (timeout_clock > 1000000)	// Timeout, send <NAK>
		{
			printf("%c",21);
			timeout_clock = 0;
		}
	}
}

/*
*	Write a page to flash memory
*
*/
void flash_write_page(uint8_t *flash_page)
{
	// Write received blocks to unused memory region
	
	
	while(1);
}

/*
*	Remove XMODEM 0x1A padding at end of data
*
*/
xmodem_clear_padding(uint8_t *buff)
{
	// Find length of buffer
	int len = strlen(buff);
	
	// Overwrite the padding element in the buffer (zero-indexed)
	while(len > 0 && buff[len-1] == 0x1A)	// Check if current element is a padding character
	{
		// Write null
		buff[len-1] = '\0';
		
		len--;
	}
	
	return;	// Padding characters removed
}
