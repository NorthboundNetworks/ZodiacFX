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
 * Authors: Paul Zanna <paul@northboundnetworks.com>
 *		  & Kristopher Chen <Kristopher@northboundnetworks.com>
 *
 */ 

#include <asf.h>
#include <string.h>
#include "stacking.h"
#include "trace.h"
#include "switch.h"
#include "lwip/def.h"
#include "openflow/openflow.h"
#include "timers.h"

/* SPI clock setting (Hz). */
static uint32_t gs_ul_spi_clock = 30000000;

/* Chip select. */
#define SPI_CHIP_SEL 0
#define SPI_CHIP_PCS spi_get_pcs(SPI_CHIP_SEL)
/* Clock polarity. */
#define SPI_CLK_POLARITY 0
/* Clock phase. */
#define SPI_CLK_PHASE 0
/* Delay before SPCK. */
#define SPI_DLYBS 0x30
/* Delay between consecutive transfers. */
#define SPI_DLYBCT 0x06

// Global variables
extern uint8_t last_port_status[8];
extern uint8_t port_status[8];
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];
extern uint8_t gs_uc_eth_buffer[GMAC_FRAME_LENTGH_MAX];
extern int OF_Version;
extern struct ofp10_port_stats phys10_port_stats[8];
extern struct ofp13_port_stats phys13_port_stats[8];

// Local variables
uint16_t spi_slave_send_size;
int32_t spi_slave_send_count;
uint8_t timer_alt;
uint8_t pending_spi_command = SPI_SEND_READY;
bool master_ready;
bool slave_ready;
uint8_t spi_dummy_bytes = 0;
struct spi_port_stats spi_p_stats;
uint8_t spi_stats_rr = 0;
struct spi_packet *spi_packet;
bool end_check;
uint8_t spi_receive_port = 0;
uint16_t spi_receive_count;
uint32_t rcv_time;

void spi_master_initialize(void);
void spi_slave_initialize(void);
void spi_port_stats(void);
void spi_port_status(void);

struct spi_debug_stats spi_debug;

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
	spi_set_bits_per_transfer(SPI_SLAVE_BASE, SPI_CHIP_SEL, SPI_CSR_BITS_16_BIT);
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
	uint32_t ul_sysclk_div = sysclk_get_cpu_hz() / gs_ul_spi_clock;
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
	spi_set_bits_per_transfer(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CSR_BITS_16_BIT);
	spi_set_baudrate_div(SPI_MASTER_BASE, SPI_CHIP_SEL, (ul_sysclk_div));
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
		// Send SLAVE port stats if SLAVE is in the clear state
		if (slave_ready == true && pending_spi_command == SPI_SEND_READY)
		{
			spi_p_stats.preamble = SPI_STATS_PREAMBLE;
			spi_p_stats.spi_size = sizeof(struct spi_port_stats);
			memcpy(&shared_buffer, &spi_p_stats, sizeof(struct spi_port_stats));
			ioport_set_pin_level(SPI_IRQ1, true);	// Set the IRQ to signal the slave wants to send something
			pending_spi_command = SPI_SEND_STATS;	// We are waiting to send port stats
			spi_slave_send_size = sizeof(struct spi_port_stats);
			spi_slave_send_count = spi_slave_send_size;
			timer_alt = 0;
		}
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

// ##################### SPI MASTER Send and Receive Functions #####################

/*
*	Master send function
*
*/
void MasterStackSend(uint8_t *p_uc_data, uint16_t ul_size, uint32_t port)
{
	uint8_t uc_pcs;
	static uint16_t data;
	uint8_t *p_buffer;
	uint8_t outport;
	
	uint8_t spi_head_buffer[SPI_HEADER_SIZE] = {0};
	
	if (port < 255)
	{
		outport = port;
		phys10_port_stats[port-1].tx_packets++;
		phys13_port_stats[port-1].tx_packets++;
	} else {
		port = 255;
		if (port_status[4] == 1) phys10_port_stats[4].tx_packets++;
		if (port_status[4] == 1) phys13_port_stats[4].tx_packets++;
		if (port_status[5] == 1) phys10_port_stats[5].tx_packets++;
		if (port_status[5] == 1) phys13_port_stats[5].tx_packets++;
		if (port_status[6] == 1) phys10_port_stats[6].tx_packets++;
		if (port_status[6] == 1) phys13_port_stats[6].tx_packets++;
		if (port_status[7] == 1) phys10_port_stats[7].tx_packets++;
		if (port_status[7] == 1) phys13_port_stats[7].tx_packets++;
	}
	// Prepare header (shared_buffer already contains the packet data)
	spi_packet = &spi_head_buffer;
	spi_packet->preamble = SPI_PACKET_PREAMBLE;
	spi_packet->ul_rcv_size = ul_size;
	spi_packet->spi_crc = 0;
	// Calculate CRC value
	for(int x = 0;x<ul_size;x++)
	{
		spi_packet->spi_crc += p_uc_data[x];
	}
	spi_packet->tag = port;
	spi_packet->spi_size = SPI_HEADER_SIZE + ul_size;
	
	TRACE("stacking.c: Sending packet to slave (%d bytes for port %d)", ul_size, port);
	
	// Send the SPI packet header
	for(uint16_t ct=0; ct<SPI_HEADER_SIZE; ct+=2)
	{
		spi_read(SPI_MASTER_BASE, NULL, NULL);
		spi_write(SPI_MASTER_BASE, *(uint16_t*)&spi_head_buffer[ct], 0, 0);
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
	}
	// Send the SPI packet body
	for(uint16_t ct=0; ct<ul_size; ct+=2)
	{
		spi_read(SPI_MASTER_BASE, NULL, NULL);
		spi_write(SPI_MASTER_BASE, *(uint16_t*)&p_uc_data[ct], 0, 0);
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
	}
	
	spi_debug.master_tx_count++;
	
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
	uint32_t spi_crc_rcv;

	spi_read_size = GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE;
	// ignore dummy bytes
	spi_read(SPI_MASTER_BASE, &shared_buffer[spi_count], &uc_pcs);
	spi_write(SPI_MASTER_BASE, 0xbb, 0, 0);
	while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
	spi_read(SPI_MASTER_BASE, &shared_buffer[spi_count], &uc_pcs);
	spi_write(SPI_MASTER_BASE, 0xbb, 0, 0);
	while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
	
	while(spi_count < spi_read_size)
	{
		// Read 2 bytes and store into buffer
		spi_read(SPI_MASTER_BASE, &data, &uc_pcs);
		shared_buffer[spi_count] = data;		// lower 8 bits
		shared_buffer[spi_count+1] = (data>>8);	// upper 8 bits
		
		spi_write(SPI_MASTER_BASE, 0xbb, 0, 0);
			// MAY CAUSE TIMING PROBLEMS
			if(spi_read_size == GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE)
			{
				if(spi_count == 4)
				{
					spi_read_size = shared_buffer[2] + (shared_buffer[3]*256);
					if(spi_read_size > GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE)
					{
						spi_read_size = GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE;
					}
				}
			}
		spi_count+=2;
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
	}
	////printf("stacking.c: ------- ------- rtt %d\r\n", sys_get_ms() - rcv_time);
	
	TRACE("stacking.c: MASTER received preamble - %x, %x", shared_buffer[0], shared_buffer[1]);
	if (!((shared_buffer[0] == 0xAB && shared_buffer[1] == 0xAB) || (shared_buffer[0] == 0xBC && shared_buffer[1] == 0xBC)))
	{
		TRACE("stacking.c: ERROR - BAD SPI HEADER PREAMBLE");
		spi_debug.master_rx_error_bad_preamble++;
		return;
	}
	
	if (shared_buffer[0] == 0xBC && shared_buffer[1] == 0xBC)
	{
		/* Process Received SPI Packet */
		spi_crc_rcv = 0;
		spi_packet = &shared_buffer;
		if (spi_packet->ul_rcv_size > GMAC_FRAME_LENTGH_MAX)
		{
			TRACE("stacking.c: ERROR - BAD PACKET SIZE");
			spi_debug.master_rx_error_bad_size++;
			return;	// Packet size is corrupt
		}
		for(int x = 0;x<spi_packet->ul_rcv_size;x++)
		{
			spi_crc_rcv += spi_packet->pkt_buffer[x];
		}
		// Make sure we received the entire packet
		if (spi_packet->spi_crc != spi_crc_rcv)
		{
			TRACE("stacking.c: Corrupt slave packet CRC mismatch %x != %x",spi_packet->spi_crc ,spi_crc_rcv);
			spi_debug.master_rx_error_bad_crc++;
			return;
		}
		TRACE("stacking.c: received packet (%d bytes)", spi_packet->ul_rcv_size);
		// Copy packet into Ethernet buffer
		memcpy(gs_uc_eth_buffer, &spi_packet->pkt_buffer, GMAC_FRAME_LENTGH_MAX);
		// Update port stats
		phys10_port_stats[spi_packet->tag-1].rx_packets++;
		phys13_port_stats[spi_packet->tag-1].rx_packets++;
		// Send packet to OpenFlow table lookup function for processing
		nnOF_tablelookup(gs_uc_eth_buffer, &spi_packet->ul_rcv_size, spi_packet->tag);
		////printf("stacking.c: ------- ------- response ok\r\n");
		spi_debug.master_rx_count++;
		return;
	}
	else if (shared_buffer[0] == 0xAB && shared_buffer[1] == 0xAB)
	{
		/* Process Received Port Stats */
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
		else if (OF_Version == 4)
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
	return;
}

// ##################### SPI SLAVE Send and Receive Functions #####################
	
/*
*	SPI interface IRQ handler
*	Used to receive data from the stacking interface
*
*/
void SPI_Handler(void)
{
	static uint16_t data;
	static uint32_t receive_timeout = 0;	// Timeout for SPI data receive (MASTER->SLAVE)
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

	if(pending_spi_command == SPI_SEND_PKT || pending_spi_command == SPI_SEND_STATS)	// Send data to master
	{
		if (spi_slave_send_count <= 0)
		{
			// Flush out last two bytes
			if (spi_dummy_bytes < 2)
			{
				spi_write(SPI_SLAVE_BASE, 0xff, 0, 0); // *****
				spi_dummy_bytes++;
				return;
			}
			pending_spi_command = SPI_SEND_READY;	// Clear the pending command
			ioport_set_pin_level(SPI_IRQ1, false);	// turn off the IRQ because we are done
			spi_dummy_bytes = 0;
		}
		else
		{
			while(spi_slave_send_count > 0)
			{
				spi_write(SPI_SLAVE_BASE, *(uint16_t*)&shared_buffer[spi_slave_send_size - spi_slave_send_count], 0, 0);
				spi_slave_send_count-=2;
				// Wait for master to send the next byte
				uint16_t timeout = 0;
				while ((spi_read_status(SPI_SLAVE_BASE) & SPI_SR_RDRF) == 0)
				{
					if(timeout > 100)
					{
						pending_spi_command = SPI_SEND_READY;	// Clear the pending command
						ioport_set_pin_level(SPI_IRQ1, false);	// turn off the IRQ because we are done
						
						spi_debug.slave_tx_error_timeout++;
						return;
					}
					else
					{
						timeout++;
					}
				}
				spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
			}
			spi_debug.slave_tx_count++;
		}
		return;
	}

	if(pending_spi_command == SPI_SEND_READY)
	{
		spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
		if (data == 0xBCBC)
		{
			pending_spi_command = SPI_RECEIVE;
		}
		return;
	}
	
	if(pending_spi_command == SPI_RECEIVE)
	{
		// ***** Modified MASTER -> SLAVE receiver *****
		static uint16_t spi_count = 2;
		static uint16_t spi_read_size = GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE;
	
		// Write preamble to SPI packet header
		shared_buffer[0] = 0xBC;
		shared_buffer[1] = 0xBC;

		/***** Receive the rest of the packet *****/		

		while(spi_count < (spi_read_size-1))
		{
			spi_write(SPI_SLAVE_BASE, 0xbb, 0, 0);
			uint16_t timeout = 0;
			while ((spi_read_status(SPI_SLAVE_BASE) & SPI_SR_RDRF) == 0)
			{
				if(timeout > 100)
				{
					pending_spi_command = SPI_SEND_READY;	// Clear the pending command
					spi_count = 2;
					spi_read_size = GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE;
					spi_debug.slave_rx_error_timeout++;
					return;
				}
				else
				{
					timeout++;
				}
			}
			spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
			
			shared_buffer[spi_count] = data;		// lower 8 bits
			shared_buffer[spi_count+1] = (data>>8);	// upper 8 bits

			if(spi_read_size == GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE && spi_count == 4)
			{
				spi_read_size = shared_buffer[2] + (shared_buffer[3]*256);
				if(spi_read_size > GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE)
				{
					// ERROR: over-sized packet data
					// Clean up and return
					pending_spi_command = SPI_SEND_READY;
					spi_count = 2;
					spi_read_size = GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE;
					spi_debug.slave_rx_error_bad_size++;
					return;
				}
			}
			
			// Increment the counter
			spi_count+=2;
		}
		
		/***** Process the received packet *****/
		
		uint32_t spi_crc_rcv = 0;
		spi_packet = &shared_buffer;
				
		// Check against maximum packet size
		if (spi_packet->ul_rcv_size > GMAC_FRAME_LENTGH_MAX)
		{
			// ERROR: payload data too large
			// Clean up and return
			pending_spi_command = SPI_SEND_READY;
			spi_count = 2;
			spi_read_size = GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE;
			spi_debug.slave_rx_error_bad_size++;
			return;
		}
		
		// Calculated CRC of the received data
		for(uint16_t ct=0; ct<spi_packet->ul_rcv_size; ct++)
		{
			spi_crc_rcv += spi_packet->pkt_buffer[ct];
		}
		
		// Check calculated CRC against received CRC
		if (spi_packet->spi_crc != spi_crc_rcv)
		{
			// ERROR: corrupt packet
			// Clean up and return
			pending_spi_command = SPI_SEND_READY;
			spi_count = 2;
			spi_read_size = GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE;
			spi_debug.slave_rx_error_bad_crc++;
			return;
		}
		
		if (spi_packet->tag == 255)
		{
			gmac_write(&spi_packet->pkt_buffer, spi_packet->ul_rcv_size, OFPP13_FLOOD, 0);
		}
		else if (spi_packet->tag <= 8)
		{
			gmac_write(&spi_packet->pkt_buffer, spi_packet->ul_rcv_size, spi_packet->tag-4, 0);
		}
		// Packet receive complete
		// Clean up and return
		pending_spi_command = SPI_SEND_READY;
		spi_count = 2;
		spi_read_size = GMAC_FRAME_LENTGH_MAX + SPI_HEADER_SIZE;
		////slavemaster_test();
		spi_debug.slave_rx_count++;
		return;
	}

}

// ##################### SPI Test Functions #####################

uint8_t masterslave_test(void)
{
	uint8_t pattern = 0;
	for(uint16_t i=0;i<1400;i++)
	{
		shared_buffer[i] = pattern++;
	}
	rcv_time = sys_get_ms();
	MasterStackSend(&shared_buffer, 1400, 8);
	return;
}

uint8_t slavemaster_test(void)
{
	// Note: the pending check may need to be moved outside of the function call
	if (slave_ready == true && pending_spi_command == SPI_SEND_READY)
	{
		// PREPARE TEST PACKET from SLAVE to MASTER
		spi_packet = &shared_buffer;
		spi_packet->preamble = SPI_PACKET_PREAMBLE;
		spi_packet->ul_rcv_size = 1400;
		spi_packet->spi_crc = 0;
		uint8_t*ind_ptr = &spi_packet->pkt_buffer;
		uint8_t walk = 0;
		for(uint16_t x = 0;x<1400;x++)
		{
			ind_ptr[x] = walk;
			spi_packet->spi_crc += walk;
			walk++;
		}
		spi_packet->tag = 2 + 4;
		spi_packet->spi_size = SPI_HEADER_SIZE + 1400;
		pending_spi_command = SPI_SEND_PKT;	// We are waiting to forward the packet
		spi_slave_send_size = spi_packet->spi_size;
		spi_slave_send_count = spi_slave_send_size;
		ioport_set_pin_level(SPI_IRQ1, true);	// Set the IRQ to signal the slave wants to send something
	}
	return;
}