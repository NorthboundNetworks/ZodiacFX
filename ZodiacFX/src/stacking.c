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
#include "openflow/openflow.h"

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
extern uint8_t last_port_status[8];
extern uint8_t port_status[8];
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];
extern int OF_Version;
extern struct ofp10_port_stats phys10_port_stats[8];
extern struct ofp13_port_stats phys13_port_stats[8];

// Local variables
uint16_t spi_slave_send_size;
uint16_t spi_slave_send_count;
uint8_t timer_alt;
uint8_t pending_spi_command = SPI_SEND_CLEAR;
bool master_ready;
bool slave_ready;
uint8_t spi_dummy_bytes = 0;
struct spi_port_stats spi_p_stats;
uint8_t spi_stats_rr = 0;
uint8_t spi_stats_buffer[sizeof(struct spi_port_stats)];
struct spi_packet *spi_packet;

void spi_master_initialize(void);
void spi_slave_initialize(void);
void spi_port_stats(void);
void spi_port_status(void);

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
		spi_port_stats();
		timer_alt = 1;
		return;
	} else if (timer_alt == 1)
	{
		spi_port_status();
		timer_alt = 2;
		return;
	} else if (timer_alt == 2)
	{
		if(slave_ready == false || pending_spi_command != SPI_SEND_CLEAR) return;		// Wait until the master acknowledges us before sending anything
		spi_p_stats.premable = SPI_STATS_PREAMBLE;
		spi_p_stats.spi_size = sizeof(struct spi_port_stats);
		memcpy(&spi_stats_buffer, &spi_p_stats, sizeof(struct spi_port_stats));
		ioport_set_pin_level(SPI_IRQ1, true);	// Set the IRQ to signal the slave wants to send something
		pending_spi_command = SPI_SEND_STATS;	// We are waiting to send port stats
		spi_slave_send_size = sizeof(struct spi_port_stats);
		spi_slave_send_count = spi_slave_send_size;
		timer_alt = 0;
		return;
	}
}

void spi_port_stats(void)
{
	spi_p_stats.tx_bytes[spi_stats_rr] += readtxbytes(spi_stats_rr+1);
	spi_p_stats.rx_bytes[spi_stats_rr] += readrxbytes(spi_stats_rr+1);
	spi_stats_rr++;
	if (spi_stats_rr == 4) spi_stats_rr = 0;
	return;
}

void spi_port_status(void)
{
	// Copy out the old status so we know if it has changed
	spi_p_stats.last_port_status[0] = spi_p_stats.port_status[0];
	spi_p_stats.last_port_status[1] = spi_p_stats.port_status[1];
	spi_p_stats.last_port_status[2] = spi_p_stats.port_status[2];
	spi_p_stats.last_port_status[3] = spi_p_stats.port_status[3];
	// Update port status
	spi_p_stats.port_status[0] = (switch_read(30) & 32) >> 5;
	spi_p_stats.port_status[1] = (switch_read(46) & 32) >> 5;
	spi_p_stats.port_status[2] = (switch_read(62) & 32) >> 5;
	spi_p_stats.port_status[3] = (switch_read(78) & 32) >> 5;
	return;
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
	static uint16_t data;
	uint8_t uc_pcs;
	int spi_count = 0;
	uint16_t spi_read_size;

	for (int i = 0; i<6;i++)
	{
		spi_write(SPI_MASTER_BASE, 0xbb, 0, 0);		// Write 1 more byte to clean out buffer
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
		if (i > 2) spi_read(SPI_MASTER_BASE, &shared_buffer[i-3], &uc_pcs);		// skip for first 2 bytes
	}
	
	if (shared_buffer[0] != 0xAB && shared_buffer[0] != 0xBC) return;
	spi_count = 4;
	spi_read_size = shared_buffer[2] + (shared_buffer[3]*256);	
	while(spi_count < spi_read_size)
	{
		for(int x = 0;x<10000;x++);
		spi_write(SPI_MASTER_BASE, 0xbb, 0, 0);
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
		spi_read(SPI_MASTER_BASE, &shared_buffer[spi_count], &uc_pcs);
		spi_count++;
	}
	
	if (shared_buffer[0] == 0xAB && shared_buffer[1] == 0xAB)		// Stats message
	{
		TRACE("stacking.c: %d bytes of port stats data received from slave", spi_count);
		memcpy(&spi_p_stats, &shared_buffer, sizeof(struct spi_port_stats));
		port_status[4] = spi_p_stats.port_status[0];
		port_status[5] = spi_p_stats.port_status[1];
		port_status[6] = spi_p_stats.port_status[2];
		port_status[7] = spi_p_stats.port_status[3];
		
		if (OF_Version == 1)
		{
			phys10_port_stats[4].tx_bytes += spi_p_stats.tx_bytes[0];
			phys10_port_stats[4].rx_bytes += spi_p_stats.rx_bytes[0];
			phys10_port_stats[5].tx_bytes += spi_p_stats.tx_bytes[1];
			phys10_port_stats[5].rx_bytes += spi_p_stats.rx_bytes[1];
			phys10_port_stats[6].tx_bytes += spi_p_stats.tx_bytes[2];
			phys10_port_stats[6].rx_bytes += spi_p_stats.rx_bytes[2];
			phys10_port_stats[7].tx_bytes += spi_p_stats.tx_bytes[3];
			phys10_port_stats[7].rx_bytes += spi_p_stats.rx_bytes[3];
		}

		if (OF_Version == 4)
		{
			phys13_port_stats[4].tx_bytes += spi_p_stats.tx_bytes[0];
			phys13_port_stats[4].rx_bytes += spi_p_stats.rx_bytes[0];
			phys13_port_stats[5].tx_bytes += spi_p_stats.tx_bytes[1];
			phys13_port_stats[5].rx_bytes += spi_p_stats.rx_bytes[1];
			phys13_port_stats[6].tx_bytes += spi_p_stats.tx_bytes[2];
			phys13_port_stats[6].rx_bytes += spi_p_stats.rx_bytes[2];
			phys13_port_stats[7].tx_bytes += spi_p_stats.tx_bytes[3];
			phys13_port_stats[7].rx_bytes += spi_p_stats.rx_bytes[3];
		}
	}
	else if (shared_buffer[0] == 0xBC && shared_buffer[1] == 0xBC)		// Stats message
	{
		TRACE("stacking.c: %d bytes of packet data received from slave", spi_count);
		spi_packet = &shared_buffer;
		nnOF_tablelookup(spi_packet->pkt_buffer, &spi_packet->ul_rcv_size, spi_packet->tag);
	} else 
	{
		TRACE("stacking.c: %d bytes of unknown data received from slave", spi_count);
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
	
	if (slave_ready == false)		// Is this the first data we have received?
	{
		if (spi_read_status(SPI_SLAVE_BASE) & SPI_SR_RDRF)
		{
			spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
			if (data == 0xaa) 
			{
				ioport_set_pin_level(SPI_IRQ1, false);	// turn off the IRQ
				slave_ready = true;
			}
			return;
		}
	}
	
	if(pending_spi_command == SPI_SEND_STATS)	// We send the master our port stats
	{
		if (spi_slave_send_count <= 0)
		{
			if (spi_dummy_bytes < 2)
			{
				spi_write(SPI_SLAVE_BASE, 0xff, 0, 0);
				spi_dummy_bytes++;
				return;
			}			
			pending_spi_command = SPI_SEND_CLEAR;	// Clear the pending command
			ioport_set_pin_level(SPI_IRQ1, false);	// turn off the IRQ because we are done
			spi_dummy_bytes = 0;
		} else {
			spi_write(SPI_SLAVE_BASE, spi_stats_buffer[spi_slave_send_size - spi_slave_send_count], 0, 0);
			spi_slave_send_count--;
		}		
		return;	
	}

	if(pending_spi_command == SPI_SEND_PKT)	// We send the master our port stats
	{
		if (spi_slave_send_count <= 0)
		{
			if (spi_dummy_bytes < 2)
			{
				spi_write(SPI_SLAVE_BASE, 0xff, 0, 0);
				spi_dummy_bytes++;
				return;
			}
			pending_spi_command = SPI_SEND_CLEAR;	// Clear the pending command
			ioport_set_pin_level(SPI_IRQ1, false);	// turn off the IRQ because we are done
			spi_dummy_bytes = 0;
		} else {
			spi_write(SPI_SLAVE_BASE, shared_buffer[spi_slave_send_size - spi_slave_send_count], 0, 0);
			spi_slave_send_count--;
		}
		return;
	}
		
	if(pending_spi_command == SPI_SEND_CLEAR)
	{
		spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
		ioport_set_pin_level(SPI_IRQ1, false);
	}
}