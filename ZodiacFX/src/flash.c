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
#include "flash.h"
#include "config_zodiac.h"
#include "openflow/openflow.h"

// Global variables
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];

// Static variables
static uint32_t page_addr;
static uint32_t ul_rc;

// Internal Functions
void xmodem_xfer(void);
void xmodem_clear_padding(uint8_t *buff);
int flash_write_page(uint8_t *flash_page);

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
	// Clear shared_buffer
	memset(&shared_buffer, 0, sizeof(shared_buffer));
	
	// Initialise page_addr variable
	page_addr = (IFLASH_ADDR + (3*IFLASH_SIZE/4) ); // Start at location 3/4 of internal flash
	
	/* Initialize flash: 6 wait states for flash writing. */
	ul_rc = flash_init(FLASH_ACCESS_MODE_128, 6);
	if (ul_rc != FLASH_RC_OK) {
		printf("flash.c: flash service initialisation error", (unsigned long)ul_rc);
		return 0;
	}
	

	
	
	xmodem_xfer();	// Receive new firmware image vie XModem
	
	/*TODO: Update main firmware image*/
	// Copy new firmware image to program location
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
				
				// Check that buffer will fit into page size (NULL not required)
				if(strlen(shared_buffer) <= 512)
				{
					if(!flash_write_page(&shared_buffer))	// TODO: Testing a image < 512 bytes, will change this to allow the full image size
					{
						printf("flash.c: page written successfully");
					}
					else
					{
						printf("flash.c: page write failed");
						return 0;
					}
				}
			}
			
			// Check for end of block
			if (block_count == 132)
			{
				if (xmodem_crc == ch)	// Check CRC
				{
					printf("%c",6);		// If the CRC is OK then send a <ACK>
					// TODO: Write a page to flash if 4 blocks received
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
int flash_write_page(uint8_t *flash_page)
{
	/* Unlock page */
	printf("flash.c: unlocking f/w page at 0x%08x\r\n", page_addr);
	ul_rc = flash_unlock(page_addr,
			page_addr + IFLASH_PAGE_SIZE - 1, 0, 0);
	if (ul_rc != FLASH_RC_OK) {
		printf("flash.c: flash unlock error %lu", (unsigned long)ul_rc);
		return 0;
	}

	// Erase sector first
	ul_rc = flash_erase_sector(page_addr);
	if (ul_rc != FLASH_RC_OK) {
		printf("flash.c: flash erase error %lu\n\r", (unsigned long)ul_rc);
		return 0;
	}

	// Write to sector
	ul_rc = flash_write(page_addr, shared_buffer,
			IFLASH_PAGE_SIZE, 0);

	if (ul_rc != FLASH_RC_OK) {
		printf("flash.c: flash write error %lu\n\r", (unsigned long)ul_rc);
		return 0;
	}
	
	
	// Clear shared_buffer
	memset(&shared_buffer, 0, sizeof(shared_buffer));
	
	// Increment page address by 512 (go to next page)
	page_addr += 512;
	
	return 1;
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
