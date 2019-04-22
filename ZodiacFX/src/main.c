/**
 * @file
 * main.c
 *
 * This file contains the initialisation and main loop
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
#include <string.h>

#include "netif/etharp.h"
#include "timers.h"
#include "lwip/init.h"
#include "lwip/timers.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/err.h"

#include "command.h"
#include "eeprom.h"
#include "switch.h"
#include "http.h"
#include "flash.h"
#include "openflow/openflow.h"
#include "ksz8795clx/ethernet_phy.h"

// Global variables
struct netif gs_net_if;
struct zodiac_config Zodiac_Config;
int charcount, charcount_last;
int portmap[4];
int32_t ul_temp;
uint8_t NativePortMatrix;
uint32_t uid_buf[4];

/** Reference voltage for AFEC,in mv. */
#define VOLT_REF        (3300)
/** The maximal digital value */
#define MAX_DIGITAL     (4095UL)

/*
*	Coverts the temp sensor voltage to temp
*
*/
static void afec_temp_sensor_end_conversion(void)
{
	volatile uint32_t g_ul_value = 0;
	int32_t ul_vol;
	g_ul_value = afec_channel_get_value(AFEC0, AFEC_TEMPERATURE_SENSOR);
	ul_vol = g_ul_value * VOLT_REF / MAX_DIGITAL;
	/*
	* According to datasheet, The output voltage VT = 1.44V at 27C
	* and the temperature slope dVT/dT = 4.7 mV/C
	*/
	ul_temp = (ul_vol - 1440)  * 100 / 470 + 27;
}

/*
*	Inialise the temp sensor
*
*/
void temp_init(void)
{
	afec_enable(AFEC0);
	struct afec_config afec_cfg;
	afec_get_config_defaults(&afec_cfg);
	afec_init(AFEC0, &afec_cfg);
	afec_set_trigger(AFEC0, AFEC_TRIG_SW);
	struct afec_ch_config afec_ch_cfg;
	afec_ch_get_config_defaults(&afec_ch_cfg);
	afec_ch_set_config(AFEC0, AFEC_TEMPERATURE_SENSOR, &afec_ch_cfg);
	afec_channel_set_analog_offset(AFEC0, AFEC_TEMPERATURE_SENSOR, 0x800);
	struct afec_temp_sensor_config afec_temp_sensor_cfg;
	afec_temp_sensor_get_config_defaults(&afec_temp_sensor_cfg);
	afec_temp_sensor_cfg.rctc = true;
	afec_temp_sensor_set_config(AFEC0, &afec_temp_sensor_cfg);
	afec_set_callback(AFEC0, AFEC_INTERRUPT_EOC_15, afec_temp_sensor_end_conversion, 1);
}

/*
*	This function is where bad code goes to die!
*	Hard faults are trapped here and won't return.
*
*/
void HardFault_Handler(void)
{
	while(1);
}

/*
*	Main program loop
*
*/
int main (void)
{
	char cCommand[64];
	char cCommand_last[64];
	memset(&cCommand, 0, sizeof(cCommand));
	memset(&cCommand_last, 0, sizeof(cCommand_last));
	cCommand[0] = '\0';
	charcount = 0;
	struct ip_addr x_ip_addr, x_net_mask, x_gateway;

	sysclk_init();
	board_init();
	get_serial(&uid_buf);

	irq_initialize_vectors(); // Initialize interrupt vector table support.

	cpu_irq_enable(); // Enable interrupts

	stdio_usb_init();
	spi_init();
	eeprom_init();
	temp_init();
	membag_init();

	loadConfig(); // Load Config
	if (Zodiac_Config.stats_interval > 30) Zodiac_Config.stats_interval = 1;	// If this value has never been set make it the default of 1

	IP4_ADDR(&x_ip_addr, Zodiac_Config.IP_address[0], Zodiac_Config.IP_address[1],Zodiac_Config.IP_address[2], Zodiac_Config.IP_address[3]);
	IP4_ADDR(&x_net_mask, Zodiac_Config.netmask[0], Zodiac_Config.netmask[1],Zodiac_Config.netmask[2], Zodiac_Config.netmask[3]);
	IP4_ADDR(&x_gateway, Zodiac_Config.gateway_address[0], Zodiac_Config.gateway_address[1],Zodiac_Config.gateway_address[2], Zodiac_Config.gateway_address[3]);

	/* Initialize KSZ8795. */
	switch_init();

	/* Initialize lwIP. */
	lwip_init();

	/* Add data to netif */
	netif_add(&gs_net_if, &x_ip_addr, &x_net_mask, &x_gateway, NULL, ethernetif_init, ethernet_input);

	/* Make it the default interface */
	netif_set_default(&gs_net_if);

	netif_set_up(&gs_net_if);

	/* Initialize timer. */
	sys_init_timing();
	
	/* Initialize HTTP server. */
	http_init();
	
	// Create port map
	int v,p;
	for (v = 0;v < MAX_VLANS;v++)
	{
		if (Zodiac_Config.vlan_list[v].uActive == 1 && Zodiac_Config.vlan_list[v].uVlanType == 1)
		{
			for(p=0;p<4;p++)
			{
				if (Zodiac_Config.vlan_list[v].portmap[p] == 1) Zodiac_Config.of_port[p] = 1; // Port is assigned to an OpenFlow VLAN
			}
		}

		if (Zodiac_Config.vlan_list[v].uActive == 1 && Zodiac_Config.vlan_list[v].uVlanType == 2)
		{
			for(p=0;p<4;p++)
			{
				if (Zodiac_Config.vlan_list[v].portmap[p] == 1)
				{
					Zodiac_Config.of_port[p] = 0; // Port is assigned to a Native VLAN
					NativePortMatrix += 1<<p;
				}
			}
		}
	}

	while(1)
	{
		task_switch(&gs_net_if);
		task_command(cCommand, cCommand_last);
		sys_check_timeouts();
		task_openflow(); 
	}
}
