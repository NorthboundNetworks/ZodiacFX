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

// Global variables
extern uint8_t last_port_status[4];
extern uint8_t port_status[4];

// Local variables
uint32_t *spi_cmd_buffer;
uint32_t spi_slv_preamble;
uint8_t spi_state = 0;
uint16_t spi_data_count = 0;
uint16_t spi_command, spi_command_size;
//bool spi_slave_send;
uint16_t spi_slave_send_size;
uint8_t timer_alt;
uint8_t pending_spi_command = SPI_SEND_CLEAR;
bool master_ready;

void spi_master_initialize(void);
void spi_slave_initialize(void);

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
	spi_set_transfer_delay(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_DLYBS, SPI_DLYBCT);
	spi_set_bits_per_transfer(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CSR_BITS_8_BIT);
	spi_set_baudrate_div(SPI_MASTER_BASE, SPI_CHIP_SEL, (sysclk_get_cpu_hz() / gs_ul_spi_clock));
	spi_set_clock_polarity(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CLK_POLARITY);
	spi_set_clock_phase(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CLK_PHASE);

	spi_enable(SPI_MASTER_BASE);
}

void Slave_timer(void)
{
	if (timer_alt == 0)
	{
		update_port_stats();
		timer_alt = 1;
		return;
	} else if (timer_alt == 1)
	{
		update_port_status();
		timer_alt = 2;
		return;
	} else if (timer_alt == 2)
	{
		if(master_ready == false) return;		// Wait until the master acknowledges us before sending anything
		ioport_set_pin_level(SPI_IRQ1, true);	// Set the IRQ to signal the slave wants to send something
		pending_spi_command = SPI_SEND_STATS;	// We are waiting to send port stats
		timer_alt = 0;
		return;
	}
}

/*
*	Master ready function
*
*/
void MasterReady(void)
{
	spi_write(SPI_MASTER_BASE, 0xaa, 0, 0);
	master_ready = true;
	return;
}

/*
*	Master send function
*
*/
void MasterStackSend(uint8_t *p_uc_data, uint16_t ul_size)
{

	return;
}

/*
*	Master receive function
*
*/
void MasterStackRcv(void)
{
	while(ioport_get_pin_level(SPI_IRQ1))
	{
		for(int x = 0;x<10000;x++);
		spi_write(SPI_MASTER_BASE, 0xaa, 0, 0);
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
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
	master_ready = true;
	
	if(pending_spi_command == SPI_SEND_STATS)	// We send the master our port stats
	{
		pending_spi_command = SPI_SEND_CLEAR;	// Clear the pending command
		ioport_set_pin_level(SPI_IRQ1, false);	// turn off the IRQ because we are done
		return;	
	}
}