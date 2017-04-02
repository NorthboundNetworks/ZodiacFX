/**
 * @file
 * stacking.c
 *
 * This file contains the stacking functions
 *
 */

/*
 * This file is part of the Zodiac FX firmware.
 * Copyright (c) 2017 Northbound Networks.
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
 *
 */ 

#include <asf.h>
#include <string.h>
#include "stacking.h"
#include "trace.h"
#include "switch.h"
#include "lwip/def.h"

/* SPI clock setting (Hz). */
static uint32_t gs_ul_spi_clock = 500000;

/* Chip select. */
#define SPI_CHIP_SEL 0
#define SPI_CHIP_PCS spi_get_pcs(SPI_CHIP_SEL)
/* Clock polarity. */
#define SPI_CLK_POLARITY 0
/* Clock phase. */
#define SPI_CLK_PHASE 0
/* Delay before SPCK. */
#define SPI_DLYBS 0x40
/* Delay between consecutive transfers. */
#define SPI_DLYBCT 0x10

#define SPI_SLAVE_PREAMBLE		0xAAAAAAAB
#define SPI_MASTER_PREAMBLE		0xBBBBBBBC
#define SPI_STATE_PREAMBLE	0
#define SPI_STATE_COMMAND	1
#define SPI_STATE_DATA		3

uint32_t *spi_cmd_buffer;
uint32_t spi_slv_preamble;
uint8_t spi_state = 0;
uint16_t spi_data_count = 0;
uint16_t spi_command, spi_command_size;
bool spi_slave_send;
uint16_t spi_slave_send_size;
uint8_t spibuffer[1];

void spi_master_initialize(void);
void spi_slave_initialize(void);
void stack_mst_write(uint8_t *rx_data, uint16_t ul_size);

/*
*	Initialize the SPI interface to MASTER or SLAVE based on the stacking jumper
*
*/
void stacking_init(bool master)
{
	if (master)
	{
		spi_slave_initialize();
		ioport_set_pin_dir(SPI_IRQ1, IOPORT_DIR_OUTPUT);
		} else {
		spi_master_initialize();
		ioport_set_pin_dir(SPI_IRQ1, IOPORT_DIR_INPUT);
	}
	return;
}

/*
*	Initialize the SPI interface as a SLAVE
*
*/
void spi_slave_initialize(void)
{
	NVIC_DisableIRQ(SPI_IRQn);
	NVIC_ClearPendingIRQ(SPI_IRQn);
	NVIC_SetPriority(SPI_IRQn, 0);
	NVIC_EnableIRQ(SPI_IRQn);

	/* Configure an SPI peripheral. */
	spi_enable_clock(SPI_SLAVE_BASE);
	spi_disable(SPI_SLAVE_BASE);
	spi_reset(SPI_SLAVE_BASE);
	spi_set_slave_mode(SPI_SLAVE_BASE);
	spi_disable_mode_fault_detect(SPI_SLAVE_BASE);
	spi_set_peripheral_chip_select_value(SPI_SLAVE_BASE, SPI_CHIP_SEL);
	spi_set_clock_polarity(SPI_SLAVE_BASE, SPI_CHIP_SEL, SPI_CLK_POLARITY);
	spi_set_clock_phase(SPI_SLAVE_BASE, SPI_CHIP_SEL, SPI_CLK_PHASE);
	spi_set_bits_per_transfer(SPI_SLAVE_BASE, SPI_CHIP_SEL, SPI_CSR_BITS_8_BIT);
	spi_enable_interrupt(SPI_SLAVE_BASE, SPI_IER_RDRF);
	spi_enable(SPI_SLAVE_BASE);
	ioport_set_pin_level(SPI_IRQ1, false);
}

/*
*	Initialize the SPI interface as a MASTER
*
*/
void spi_master_initialize(void)
{
	/* Configure an SPI peripheral. */
	spi_enable_clock(SPI_MASTER_BASE);
	spi_disable(SPI_MASTER_BASE);
	spi_reset(SPI_MASTER_BASE);
	spi_set_lastxfer(SPI_MASTER_BASE);
	spi_set_master_mode(SPI_MASTER_BASE);
	spi_disable_mode_fault_detect(SPI_MASTER_BASE);
	spi_disable_loopback(SPI_MASTER_BASE);
	spi_set_peripheral_chip_select_value(SPI_MASTER_BASE, SPI_CHIP_SEL);
	//spi_set_fixed_peripheral_select(SPI_MASTER_BASE);
	//spi_disable_peripheral_select_decode(SPI_MASTER_BASE);
	spi_set_transfer_delay(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_DLYBS, SPI_DLYBCT);
	spi_set_bits_per_transfer(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CSR_BITS_8_BIT);
	spi_set_baudrate_div(SPI_MASTER_BASE, SPI_CHIP_SEL, (sysclk_get_cpu_hz() / gs_ul_spi_clock));
	//spi_configure_cs_behavior(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CS_KEEP_LOW);
	spi_set_clock_polarity(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CLK_POLARITY);
	spi_set_clock_phase(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CLK_PHASE);

	spi_enable(SPI_MASTER_BASE);
}


void MasterStackSend(uint8_t *p_uc_data, uint16_t ul_size)
{
	uint32_t cmd_buffer;
	
	// Send the preamble mark the beginning of a transfer
	cmd_buffer = ntohl(SPI_SLAVE_PREAMBLE);
	stack_mst_write(&cmd_buffer, sizeof(cmd_buffer));
	
	// Send a 2 byte command code and 2 byte data code
	cmd_buffer = ntohl(ul_size);
	stack_mst_write(&cmd_buffer, sizeof(cmd_buffer));
	
	// Send packet
	stack_mst_write(p_uc_data, ul_size);
	return;
}

void MasterStackRcv(void)
{
	uint32_t cmd_buffer;
	
	TRACE("switch.c: Master received slave IRQ!");
	// Send the preamble mark the beginning of a transfer
	cmd_buffer = ntohl(SPI_MASTER_PREAMBLE);
	stack_mst_write(&cmd_buffer, sizeof(cmd_buffer));

	// Send 4 bytes to receive slave packet size
	cmd_buffer = 0xFFFFFFFF;
	stack_mst_write(&cmd_buffer, sizeof(cmd_buffer));
	TRACE("switch.c: Rcv Size = %04X", cmd_buffer);
	while(ioport_get_pin_level(SPI_IRQ1));
}

/*
*	Write to the SPI stacking interface
*
*/
void stack_mst_write(uint8_t *rx_data, uint16_t ul_size)
{
	uint8_t uc_pcs;
	static uint16_t data;
	uint8_t *p_buffer;
	
	p_buffer = rx_data;
	
	for (int i = 0; i < ul_size; i++) {
		for(int x = 0;x<10000;x++);
		spi_write(SPI_MASTER_BASE, p_buffer[i], 0, 0);
		TRACE("switch.c: SPI Write - %d , %02X", i, p_buffer[i]);
		/* Wait transfer done. */
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
		//spi_read(SPI_MASTER_BASE, p_buffer[i], &uc_pcs);
		TRACE("switch.c: SPI Read - %d , %02X", i, data);
	}
	return;
}
	



/*
*	SPI interface IRQ handler
*	Used to receive data from the stacking interface
*
*/
void SPI_Handler(void)
{
	static uint16_t data;
	uint8_t uc_pcs;

	if (spi_slave_send == false)
	{
		if (spi_read_status(SPI_SLAVE_BASE) & SPI_SR_RDRF)
		{
			spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
			//TRACE("%d - %02X", spi_data_count, data);

			if (spi_state == SPI_STATE_DATA)
			{
				spibuffer[spi_data_count] = data;
				spi_data_count++;
				if (spi_data_count == spi_command_size)
				{
					TRACE("switch.c: %d bytes of Data received", spi_data_count);
					uint8_t* tail_tag = (uint8_t*)(spibuffer + (int)(spi_command_size)-1);
					uint8_t tag = *tail_tag + 1;
					TRACE("switch.c: Tag = %d", tag);
					gmac_write(spibuffer, spi_data_count-1, tag);
					spi_data_count = 0;
					spi_state = SPI_STATE_PREAMBLE;
					return;
				}
			}

			//	Start of Preamble
			if (spi_state == SPI_STATE_PREAMBLE && data == 0xAA)
			{
				switch (spi_data_count)
				{
					case 0:
					spi_data_count = 1;
					break;
					
					case 1:
					spi_data_count = 2;
					break;
					
					case 2:
					spi_data_count = 3;
					break;
				}
			}
			
			//	End of Preamble
			if (spi_state == SPI_STATE_PREAMBLE && data == 0xAB && spi_data_count == 3)
			{
				spi_state = SPI_STATE_COMMAND;
				spi_data_count = 0;
				TRACE("switch.c: Master send preamble received!");
				return;
			}
			// Command bytes
			if (spi_state == SPI_STATE_COMMAND)
			{
				switch(spi_data_count)
				{
					case 0:
					spi_command = data;
					spi_data_count++;
					break;
					
					case 1:
					spi_command = data<<8;
					spi_data_count++;
					break;
					
					case 2:
					spi_command_size = data<<8;
					spi_data_count++;
					break;
					case 3:
					spi_command_size += data;
					spi_state = SPI_STATE_DATA;
					spi_data_count = 0;
					TRACE("switch.c: Command received! %d - %d", spi_command, spi_command_size);
					break;
				}
			}
			
		}
		return;
		
	} else
	{
		if (spi_read_status(SPI_SLAVE_BASE) & SPI_SR_RDRF)
		{
			spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
			TRACE("switch.c: %d - %02X (%d)", spi_data_count, data, spi_state);

			//	Start of Preamble
			if (spi_state == SPI_STATE_PREAMBLE && data == 0xBB)
			{
				switch (spi_data_count)
				{
					case 0:
					spi_data_count = 1;
					spi_write(SPI_SLAVE_BASE, 0xFF, 0, 0);
					break;
					
					case 1:
					spi_data_count = 2;
					spi_write(SPI_SLAVE_BASE, 0xFF, 0, 0);
					break;
					
					case 2:
					spi_data_count = 3;
					spi_write(SPI_SLAVE_BASE, 0xFF, 0, 0);
					break;
				}
				return;
			}
			
			//	End of Preamble
			if (spi_state == SPI_STATE_PREAMBLE && data == 0xBC && spi_data_count == 3)
			{
				spi_state = SPI_STATE_COMMAND;
				spi_write(SPI_SLAVE_BASE, data, 0, 0);
				spi_data_count = 0;
				TRACE("switch.c: Slave send reamble received!");
				return;
			}
			// Command bytes
			if (spi_state == SPI_STATE_COMMAND)
			{
				switch(spi_data_count)
				{
					case 0:
					spi_command = data;
					spi_write(SPI_SLAVE_BASE, 0xFF, 0, 0);
					spi_data_count++;
					break;
					
					case 1:
					spi_command = data<<8;
					spi_write(SPI_SLAVE_BASE, spi_slave_send_size >> 8, 0, 0); // Size
					spi_data_count++;
					break;
					
					case 2:
					spi_command_size = data<<8;
					spi_write(SPI_SLAVE_BASE, spi_slave_send_size, 0, 0); // Size
					spi_data_count++;
					break;
					case 3:
					spi_command_size += data;
					spi_state = SPI_STATE_DATA;
					spi_write(SPI_SLAVE_BASE, 0xFF, 0, 0);
					spi_data_count = 0;
					//TRACE("Master fill received! %d - %d", spi_command, spi_command_size);
					TRACE("switch.c: Packet Size = 0x%X (%d)", spi_slave_send_size, spi_slave_send_size);
					break;
				}
			}
			
			if (spi_state == SPI_STATE_DATA)
			{
				ioport_set_pin_level(SPI_IRQ1, false);
				spi_slave_send = false;
				TRACE("switch.c: Set Slave to false!");
				spi_state = SPI_STATE_PREAMBLE;
				return;
			}
		}
		return;
	}
}