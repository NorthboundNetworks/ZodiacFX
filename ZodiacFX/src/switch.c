/**
 * @file
 * switch.c
 *
 * This file contains the initialization and functions for KSZ8795
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
 * Author: Paul Zanna <paul@northboundnetworks.com>
 *
 */

#include <asf.h>
#include <stdlib.h>
#include <string.h>
#include "trace.h"
#include "openflow/openflow.h"
#include "switch.h"
#include "conf_eth.h"
#include "command.h"

#include "ksz8795clx/ethernet_phy.h"
#include "netif/etharp.h"

/** The GMAC driver instance */
gmac_device_t gs_gmac_dev;
extern struct tcp_conn tcp_conn;
extern struct zodiac_config Zodiac_Config;
extern int OF_Version;
uint8_t gmacbuffer[GMAC_FRAME_LENTGH_MAX];
uint8_t spibuffer[GMAC_FRAME_LENTGH_MAX];
struct ofp10_port_stats phys10_port_stats[4];
struct ofp13_port_stats phys13_port_stats[4];
uint8_t port_status[4];
extern uint8_t NativePortMatrix;
extern bool masterselect;
extern bool stackenabled;
/** Buffer for ethernet packets */
static volatile uint8_t gs_uc_eth_buffer[GMAC_FRAME_LENTGH_MAX];

/* SPI clock setting (Hz). */
static uint32_t gs_ul_spi_clock = 500000;

/* GMAC HW configurations */
#define BOARD_GMAC_PHY_ADDR 0
/** First Status Command Register - Second Dummy Data */
#define USART_SPI                   USART0
#define USART_SPI_DEVICE_ID         1
#define USART_SPI_BAUDRATE          1000000

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

#define SPI_PREAMBLE		0xAAAAAAAB
#define SPI_STATE_PREAMBLE	0
#define SPI_STATE_COMMAND	1
#define SPI_STATE_DATA		3

uint8_t stats_rr = 0;

uint32_t *spi_cmd_buffer;
uint8_t spi_state = 0;
uint16_t spi_data_count = 0;
uint16_t spi_command, spi_command_size;
bool spi_slave_send; 

// Internal functions
int readtxbytes(int port);
int readrxbytes(int port);
int readtxdrop(int port);
int readrxdrop(int port);
int readrxcrcerr(int port);
void spi_master_initialize(void);
void spi_slave_initialize(void);
void stack_mst_write(uint8_t *rx_data, uint16_t ul_size);


struct usart_spi_device USART_SPI_DEVICE = {
	 /* Board specific select ID. */
	 .id = USART_SPI_DEVICE_ID
 };

/*
*	Initialise the SPI interface for the switch
*
*/
void spi_init(void)
{
	/* Config the USART_SPI for KSZ8795 interface */
	usart_spi_init(USART_SPI);
	usart_spi_setup_device(USART_SPI, &USART_SPI_DEVICE, SPI_MODE_3, USART_SPI_BAUDRATE, 0);
	usart_spi_enable(USART_SPI);
}


void stack_process(uint8_t *p_uc_data, uint16_t ul_size)
{
	uint32_t cmd_buffer;
	
	// Send the preamble mark the beginning of a transfer
	cmd_buffer = ntohl(SPI_PREAMBLE);
	stack_mst_write(&cmd_buffer, sizeof(cmd_buffer));
	
	// Send a 2 byte command code and 2 byte data code
	cmd_buffer = ntohl(ul_size);
	stack_mst_write(&cmd_buffer, sizeof(cmd_buffer));
	
	// Send packet
	stack_mst_write(p_uc_data, ul_size);
	return;
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
		for(int x = 0;x<5000;x++);
		spi_write(SPI_MASTER_BASE, p_buffer[i], 0, 0);
		TRACE("%d , %02X", i, p_buffer[i]);
		/* Wait transfer done. */
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
		spi_read(SPI_MASTER_BASE, &rx_data, &uc_pcs);
		
	}
	TRACE("\r\n");
	return;
}

/*
*	Initialize the SPI interface to MASTER or SLAVE based on the stacking jumper
*
*/
void stacking_init(bool master)
{
	if (master){
		spi_slave_initialize();
	} else {
		spi_master_initialize();
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
					TRACE("%d bytes of Data received", spi_data_count);
					uint8_t* tail_tag = (uint8_t*)(spibuffer + (int)(spi_command_size)-1);
					uint8_t tag = *tail_tag + 1;
					TRACE("Tag = %d", tag);
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
				TRACE("Preamble received!");
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
						TRACE("Command received! %d - %d", spi_command, spi_command_size);
						break;
				}
			}
		
		}	
	return;
	
	} else
	{
		spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
		TRACE("Slave read %X (%d)", data, spi_data_count);
		spi_data_count++;
		if (spi_data_count > 2)
		{
			ioport_set_pin_level(SPI_IRQ1, false);
			spi_slave_send = false;
			TRACE("Set Slave to false!");
			spi_data_count = 0;	
		}

	}
	
}

/*
*	Read from the switch registers
*
*/
int switch_read(uint8_t param1)
{
	uint8_t reg[2];

	if (param1 < 128) {
		reg[0] = 96;
		} else {
		reg[0] = 97;
	}

	reg[1] = param1 << 1;

	/* Select the DF memory to check. */
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);

	/* Send the Manufacturer ID Read command. */
	usart_spi_write_packet(USART_SPI, reg, 2);

	/* Receive Manufacturer ID. */
	usart_spi_read_packet(USART_SPI, reg, 1);

	/* Deselect the checked DF memory. */
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);

	return reg[0];
}

/*
*	Write to the switch registers
*
*/
int switch_write(uint8_t param1, uint8_t param2)
{
	uint8_t reg[3];

	if (param1 < 128) {
		reg[0] = 64;
		} else {
		reg[0] = 65;
	}

	reg[1] = param1 << 1;
	reg[2] = param2;

	/* Select the DF memory to check. */
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);

	/* Send the Manufacturer ID Read command. */
	usart_spi_write_packet(USART_SPI, reg, 3);

	/* Deselect the checked DF memory. */
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	for(int x = 0;x<100000;x++);

	return switch_read(param1);
}

/*
*	Disable OpenFlow functionality
*
*/
void disableOF(void)
{
	switch_write(21,0);
	switch_write(37,0);
	switch_write(53,0);
	switch_write(69,0);
	clear_flows();

}

/*
*	Enable OpenFlow functionality
*
*/
void enableOF(void)
{
	if (Zodiac_Config.of_port[0] == 1) switch_write(21,3);
	if (Zodiac_Config.of_port[1] == 1) switch_write(37,3);
	if (Zodiac_Config.of_port[2] == 1) switch_write(53,3);
	if (Zodiac_Config.of_port[3] == 1) switch_write(69,3);
}

/*
*	Update the port stats counters
*
*	Getting the port stats can has a significant impact on performance.
*	It can take over 100ms to get a response so we only query one port per call
*/
void update_port_stats(void)
{
	if (OF_Version == 1)
	{
		phys10_port_stats[stats_rr].tx_bytes += readtxbytes(stats_rr+1);
		phys10_port_stats[stats_rr].rx_bytes += readrxbytes(stats_rr+1);
		phys10_port_stats[stats_rr].tx_dropped += readtxdrop(stats_rr+1);
		phys10_port_stats[stats_rr].rx_dropped += readrxdrop(stats_rr+1);
		phys10_port_stats[stats_rr].rx_crc_err += readrxdrop(stats_rr+1);
	}

	if (OF_Version == 4)
	{
		phys13_port_stats[stats_rr].tx_bytes += readtxbytes(stats_rr+1);
		phys13_port_stats[stats_rr].rx_bytes += readrxbytes(stats_rr+1);
		phys13_port_stats[stats_rr].tx_dropped += readtxdrop(stats_rr+1);
		phys13_port_stats[stats_rr].rx_dropped += readrxdrop(stats_rr+1);
		phys13_port_stats[stats_rr].rx_crc_err += readrxdrop(stats_rr+1);
	}
	stats_rr++;
	if (stats_rr == 4) stats_rr = 0;
}

/*
*	Read the number of CRC errors from the switch
*
*	@param port - the number of the port to get the stats for.
*
*/
int readrxcrcerr(int port)
{
	int total = 0;
	uint8_t reg = (6 + (32*(port-1)));
	switch_write(110,28);
	switch_write(111, reg);
	total += (switch_read(119) * 256);
	total += switch_read(120);
	return total;
}

/*
*	Read the number of received bytes from the switch
*
*	@param port - the number of the port to get the stats for.
*
*/
int readtxbytes(int port)
{
	int total = 0;
	uint8_t reg = (1 + (4*(port-1)));
	switch_write(110,29);
	switch_write(111, reg);
	total += (switch_read(119) * 256);
	total += switch_read(120);
	return total;
}

/*
*	Read the number of transmitted bytes from the switch
*
*	@param port - the number of the port to get the stats for.
*
*/
int readrxbytes(int port)
{
	int total = 0;
	uint8_t reg = (4*(port-1));
	switch_write(110,29);
	switch_write(111, reg);
	total += (switch_read(119) * 256);
	total += switch_read(120);
	return total;
}

/*
*	Read the number of dropped RX packets from the switch
*
*	@param port - the number of the port to get the stats for.
*
*/
int readrxdrop(int port)
{
	int total = 0;
	uint8_t reg = (2 + (4*(port-1)));
	switch_write(110,29);
	switch_write(111, reg);
	total += (switch_read(119) * 256);
	total += switch_read(120);
	return total;
}

/*
*	Read the number of dropped TX packets from the switch
*
*	@param port - the number of the port to get the stats for.
*
*/
int readtxdrop(int port)
{
	int total = 0;
	uint8_t reg = (3 + (4*(port-1)));
	switch_write(110,29);
	switch_write(111, reg);
	total += (switch_read(119) * 256);
	total += switch_read(120);
	return total;
}

/*
*	Updates the port status
*
*/
void update_port_status(void)
{
	port_status[0] = (switch_read(30) & 32) >> 5;
	port_status[1] = (switch_read(46) & 32) >> 5;
	port_status[2] = (switch_read(62) & 32) >> 5;
	port_status[3] = (switch_read(78) & 32) >> 5;
	return;
}

/*
*	GMAC write function
*
*	@param *p_buffer - pointer to the buffer containing the data to send.
*	@param ul_size - size of the data.
*	@param port - the port to send the data out from.
*
*/
void gmac_write(uint8_t *p_buffer, uint16_t ul_size, uint8_t port)
{
	if (ul_size > GMAC_FRAME_LENTGH_MAX)
	{
		return;
	}

	if (port & 1) phys10_port_stats[0].tx_packets++;
	if (port & 2) phys10_port_stats[1].tx_packets++;
	if (port & 4) phys10_port_stats[2].tx_packets++;
	if (port & 8) phys10_port_stats[3].tx_packets++;
	if (port & 1) phys13_port_stats[0].tx_packets++;
	if (port & 2) phys13_port_stats[1].tx_packets++;
	if (port & 4) phys13_port_stats[2].tx_packets++;
	if (port & 8) phys13_port_stats[3].tx_packets++;
	// Add padding
	if (ul_size < 60)
	{
		memset(&gmacbuffer, 0, 61);
		memcpy(&gmacbuffer,p_buffer, ul_size);
		uint8_t *last_byte;
		last_byte = gmacbuffer + 60;
		*last_byte = port;
		gmac_dev_write(&gs_gmac_dev, &gmacbuffer, 61, NULL);
	} else {
		memcpy(&gmacbuffer,p_buffer, ul_size);
		uint8_t *last_byte;
		last_byte = gmacbuffer + ul_size;
		*last_byte = port;
		ul_size++; // Increase packet size by 1 to allow for the tail tag.
		uint32_t write_size = gmac_dev_write(&gs_gmac_dev, &gmacbuffer, ul_size, NULL);
	}
	return;
}

/*
*	GMAC handler function
*
*/
void GMAC_Handler(void)
{
	gmac_handler(&gs_gmac_dev);
}

/*
*	Switch initialisation function
*
*/
void switch_init(void)
{
		volatile uint32_t ul_delay;
		gmac_options_t gmac_option;

		/* Wait for PHY to be ready (CAT811: Max400ms) */
		ul_delay = sysclk_get_cpu_hz() / 1000 / 3 * 400;
		while (ul_delay--);

		/* Enable GMAC clock */
		pmc_enable_periph_clk(ID_GMAC);

		/* Fill in GMAC options */
		gmac_option.uc_copy_all_frame = 1;
		gmac_option.uc_no_boardcast = 0;
		gmac_option.uc_mac_addr[0] = Zodiac_Config.MAC_address[0];
		gmac_option.uc_mac_addr[1] = Zodiac_Config.MAC_address[1];
		gmac_option.uc_mac_addr[2] = Zodiac_Config.MAC_address[2];
		gmac_option.uc_mac_addr[3] = Zodiac_Config.MAC_address[3];
		gmac_option.uc_mac_addr[4] = Zodiac_Config.MAC_address[4];
		gmac_option.uc_mac_addr[5] = Zodiac_Config.MAC_address[5];
		gs_gmac_dev.p_hw = GMAC;

		/* Init KSZ8795 registers */
		switch_write(86,232);	// Set CPU interface to MII
		switch_write(12,70);	// Turn on tail tag mode

		/* Because we use the tail tag mode on the KS8795 the additional
		byte on the end makes the frame size 1519 bytes. This causes the packet
		to fail the Max Legal size check, so setting byte 1 on global register 4
		disables the check */
		switch_write(4,242);

		/* Init GMAC driver structure */
		gmac_dev_init(GMAC, &gs_gmac_dev, &gmac_option);

		/* Enable Interrupt */
		NVIC_EnableIRQ(GMAC_IRQn);

		/* Init MAC PHY driver */
		if (ethernet_phy_init(GMAC, BOARD_GMAC_PHY_ADDR, sysclk_get_cpu_hz()) != GMAC_OK) {
			return;
		}

		while (ethernet_phy_set_link(GMAC, BOARD_GMAC_PHY_ADDR, 1) != GMAC_OK) {
			return;
		}

		// clear port stat counters
		memset(&phys10_port_stats, 0, sizeof(struct ofp10_port_stats)*4);

		/* Create KSZ8795 VLANs */
		switch_write(5,0);		// Disable 802.1q

		for (int x=0;x<MAX_VLANS;x++)
		{
			if (Zodiac_Config.vlan_list[x].uActive == 1)
			{
				if (Zodiac_Config.vlan_list[x].uVlanType == 2) switch_write(84,Zodiac_Config.vlan_list[x].uVlanID);	// If the VLAN is type Native then add the CPU port
				/* Assign the default ingress VID */
				for (int i=0;i<4;i++)
				{
					if (Zodiac_Config.vlan_list[x].portmap[i] == 1)
					{
						switch_write(20 + (i*16),Zodiac_Config.vlan_list[x].uVlanID);	// Default ingress VID
					}
				}
				/* Add entry into the VLAN table */
				int vlanoffset = Zodiac_Config.vlan_list[x].uVlanID / 4;
				int vlanindex = Zodiac_Config.vlan_list[x].uVlanID - (vlanoffset*4);
				switch_write(110,20);	// Set read VLAN flag
				switch_write(111, vlanoffset);	// Read entries 0-3

				/* Calculate format */
				uint8_t vlanmaphigh;
				uint8_t vlanmaplow;
				vlanmaphigh = 16; // Set valid bit
				if (Zodiac_Config.vlan_list[x].uVlanType == 2) vlanmaphigh += 8; // Port 5 (CPU);
				if (Zodiac_Config.vlan_list[x].portmap[3] == 1) vlanmaphigh += 4; // Port 4;
				if (Zodiac_Config.vlan_list[x].portmap[2] == 1) vlanmaphigh += 2; // Port 3;
				if (Zodiac_Config.vlan_list[x].portmap[1] == 1) vlanmaphigh += 1; // Port 2;
				vlanmaplow = x+1;	// FID = VLAN index number
				if (Zodiac_Config.vlan_list[x].portmap[0] == 1) vlanmaplow += 128; // Port 1;
				/* Write settings back to registers */
				switch_write((119-(vlanindex*2)),vlanmaphigh);
				switch_write((120-(vlanindex*2)),vlanmaplow);
				switch_write(110,4);	// Set read VLAN flag
				switch_write(111,vlanoffset);	// Read entries 0-3
			}
		}

		switch_write(5,128);	// Enable 802.1q
		disableOF(); // clear all port settings
		if (Zodiac_Config.OFEnabled == OF_ENABLED) enableOF();
		return;
}
/*
*	Main switching loop
*
*	@param *netif - pointer to the network interface struct.
*
*/
void task_switch(struct netif *netif)
{
	uint32_t ul_rcv_size = 0;
	uint8_t tag = 0;
	int8_t in_port = 0;
			
	// Check if the slave device has a packet to send us
	if(ioport_get_pin_level(SPI_IRQ1) && stackenabled == true)
	{
		TRACE("SPI Slave IRQ!");
		uint32_t cmd_buffer;
			
		// Send the preamble mark the beginning of a transfer
		cmd_buffer = 0xA1A2A3A4;
		stack_mst_write(&cmd_buffer, sizeof(cmd_buffer));
		TRACE("Slave response = %X", cmd_buffer);
	}	

	/* Main packet processing loop */
	uint32_t dev_read = gmac_dev_read(&gs_gmac_dev, (uint8_t *) gs_uc_eth_buffer, sizeof(gs_uc_eth_buffer), &ul_rcv_size);
	if (dev_read == GMAC_OK)
	{
		// Check that the frame is not corrupt
		uint16_t eth_prot;
		memcpy(&eth_prot, gs_uc_eth_buffer + 12, 2);
		eth_prot = ntohs(eth_prot);
		if (eth_prot != 0x0800 && eth_prot != 0x0806 && eth_prot != 0x86DD && eth_prot != 0x0842 && eth_prot != 0x8100)
		{
			TRACE("Invalid EtherType: %X, dropping packet!", eth_prot);
			return;
		}
		
		if(masterselect == false)	// Only process packets if board is set to MASTER
		{
			if (ul_rcv_size > 0)
			{
				uint8_t* tail_tag = (uint8_t*)(gs_uc_eth_buffer + (int)(ul_rcv_size)-1);
				uint8_t tag = *tail_tag + 1;
				if (Zodiac_Config.OFEnabled == OF_ENABLED && Zodiac_Config.of_port[tag-1] == 1)
				{
					stack_process((uint8_t *) gs_uc_eth_buffer, ul_rcv_size);
					phys10_port_stats[tag-1].rx_packets++;
					phys13_port_stats[tag-1].rx_packets++;
					ul_rcv_size--; // remove the tail first
					nnOF_tablelookup((uint8_t *) gs_uc_eth_buffer, &ul_rcv_size, tag);
					return;
				} else {
					TRACE("%d byte received from controller", ul_rcv_size);
					struct pbuf *p;
					p = pbuf_alloc(PBUF_RAW, ul_rcv_size+1, PBUF_POOL);
					memcpy(p->payload, &gs_uc_eth_buffer,(ul_rcv_size-1));
					p->len = ul_rcv_size-1;
					p->tot_len = ul_rcv_size-1;
					netif->input(p, netif);
					pbuf_free(p);
					return;
				}
			}
		} else
		{
			TRACE("Set Slave to true!");
			spi_slave_send = true;
			ioport_set_pin_level(SPI_IRQ1, true);
			return;
		}
	}
	return;

}
