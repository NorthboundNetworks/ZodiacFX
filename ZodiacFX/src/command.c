/**
 * @file
 * command.c
 *
 * This file contains the command line functions
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
 *		 & Kristopher Chen <Kristopher@northboundnetworks.com>
 *
 */

#include <asf.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "config_zodiac.h"
#include "command.h"
#include "conf_eth.h"
#include "eeprom.h"
#include "switch.h"
#include "flash.h"
#include "openflow/openflow.h"
#include "openflow/of_helper.h"
#include "lwip/def.h"
#include "timers.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

#define RSTC_KEY  0xA5000000

// Global variables
extern struct zodiac_config Zodiac_Config;
extern struct verification_data verify;
extern bool debug_output;

extern int charcount, charcount_last;
extern struct ofp_flow_mod *flow_match10[MAX_FLOWS_10];
extern struct ofp13_flow_mod *flow_match13[MAX_FLOWS_13];
extern uint8_t *ofp13_oxm_match[MAX_FLOWS_13];
extern uint8_t *ofp13_oxm_inst[MAX_FLOWS_13];
extern uint16_t ofp13_oxm_inst_size[MAX_FLOWS_13];
extern struct flows_counter flow_counters[MAX_FLOWS_13];
extern struct flow_tbl_actions *flow_actions10[MAX_FLOWS_13];
extern int iLastFlow;
extern struct ofp10_port_stats phys10_port_stats[4];
extern struct ofp13_port_stats phys13_port_stats[4];
extern struct table_counter table_counters[MAX_TABLES];
extern struct meter_entry13 *meter_entry[MAX_METER_13];
extern struct meter_band_stats_array band_stats_array[MAX_METER_13];
extern bool masterselect;
extern bool stackenabled = false;
extern bool trace = false;
extern struct tcp_pcb *tcp_pcb;
extern uint8_t port_status[4];
extern int totaltime;
extern int32_t ul_temp;
extern int OF_Version;
extern uint32_t uid_buf[4];
extern bool restart_required_outer;

// Local Variables
bool showintro = true;
uint8_t uCLIContext = 0;
struct arp_header arp_test;
uint8_t esc_char = 0;


// Internal Functions
void saveConfig(void);
void command_root(char *command, char *param1, char *param2, char *param3);
void command_config(char *command, char *param1, char *param2, char *param3);
void command_openflow(char *command, char *param1, char *param2, char *param3);
void command_debug(char *command, char *param1, char *param2, char *param3);
void printintro(void);
void printhelp(void);


/*
*	Converts a 64bit value from host to network format
*
*	@param n - value to convert
*
*/
static inline uint64_t (htonll)(uint64_t n)
{
	return HTONL(1) == 1 ? n : ((uint64_t) HTONL(n) << 32) | HTONL(n >> 32);
}

/*
*	Load the configuration settings from EEPROM
*
*/
void loadConfig(void)
{
	eeprom_read();
	return;
}

/*
*	Save the configuration settings to EEPROM
*
*/
void saveConfig(void)
{
	eeprom_write();
	return;
}

/*
*	Restart Zodiac FX
*
*/
void software_reset(void)
{
	for(int x = 0;x<100000;x++);	// Let the above message get sent to the terminal before detaching
	udc_detach();	// Detach the USB device before restart
	rstc_start_software_reset(RSTC);	// Software reset
	while (1);
}

/*
*	Main command line loop
*
*	@param str - pointer to the current command string
*	@param str_last - pointer to the last command string
*/
void task_command(char *str, char *str_last)
{
	char ch;
	char *command;
	char *param1;
	char *param2;
	char *param3;
	char *pch;

	if(restart_required_outer == true)
	{
		printf("Restarting the Zodiac FX, please reopen your terminal application.\r\n");
		software_reset();
	}

	while(udi_cdc_is_rx_ready()){
		ch = udi_cdc_getc();

		if (trace == true) trace = false;

		if (showintro == true)	// Show the intro only on the first key press
		{
			printintro();
			showintro = false;
			ch = 13;
		}
		if (ch == 27) // Is this the start of an escape key sequence?
		{
			esc_char = 1;
			return;
		}
		if (ch == 91 && esc_char == 1) // Second key in the escape key sequence?
		{
			esc_char = 2;
			return;
		}
		if (ch == 65 && esc_char == 2 && charcount == 0)	// Last char for the escape sequence for the up arrow (ascii codes 27,91,65)
		{
			strcpy(str, str_last);
			charcount = charcount_last;
			printf("%s",str);
			esc_char = 0;
			return;
		}

		if (ch == 13)	// Enter Key
		{
			printf("\r\n");
			str[charcount] = '\0';
			strcpy(str_last, str);
			charcount_last = charcount;
			pch = strtok (str," ");
			command = pch;
			pch = strtok (NULL, " ");
			param1 = pch;
			pch = strtok (NULL, " ");
			param2 = pch;
			pch = strtok (NULL, " ");
			param3 = pch;

			if (charcount > 0)
			{
				switch(uCLIContext)
				{
					case CLI_ROOT:
					command_root(command, param1, param2, param3);
					break;

					case CLI_CONFIG:
					command_config(command, param1, param2, param3);
					break;

					case CLI_OPENFLOW:
					command_openflow(command, param1, param2, param3);
					break;

					case CLI_DEBUG:
					command_debug(command, param1, param2, param3);
					break;
				};
			}

			switch(uCLIContext)
			{
				case CLI_ROOT:
				printf("%s# ",Zodiac_Config.device_name);
				break;

				case CLI_CONFIG:
				printf("%s(config)# ",Zodiac_Config.device_name);
				break;

				case CLI_OPENFLOW:
				printf("%s(openflow)# ",Zodiac_Config.device_name);
				break;

				case CLI_DEBUG:
				printf("%s(debug)# ",Zodiac_Config.device_name);
				break;
			};
			charcount = 0;
			str[0] = '\0';
			esc_char = 0;
			return;

		} else if ((ch == 127 || ch == 8) && charcount > 0)	// Backspace key
		{
			charcount--;
			char tempstr[64];
			tempstr[0] = '\0';
			strncat(tempstr,str,charcount);
			strcpy(str, tempstr);
			printf("%c",ch); // echo to output
			esc_char = 0;
			return;

		} else if (charcount < 63 && ch > 31 && ch < 127 && esc_char == 0)	// Alphanumeric key
		{
			strncat(str,&ch,1);
			charcount++;
			printf("%c",ch); // echo to output
			esc_char = 0;
			return;
		}

		if (esc_char > 0) esc_char = 0; // If the escape key wasn't up arrow (ascii 65) then clear to flag
	}
}

/*
*	Commands within the root context
*
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void command_root(char *command, char *param1, char *param2, char *param3)
{
	// Change context
	if (strcmp(command, "config")==0){
		uCLIContext = CLI_CONFIG;
		return;
	}

	if (strcmp(command, "openflow")==0){
		uCLIContext = CLI_OPENFLOW;
		return;
	}

	if (strcmp(command, "debug")==0){
		uCLIContext = CLI_DEBUG;
		return;
	}

	// Update firmware
	if (strcmp(command, "update") == 0)
	{
		printf("Please begin firmware upload\r\n");
		cli_update();
		
		return;

	}
	
	// Display help
	if (strcmp(command, "help") == 0)
	{
		printhelp();
		return;

	}

	// Display firmware version
	if (strcmp(command, "show") == 0 && strcmp(param1, "version") == 0)
	{
		printf("Firmware version: %s\r\n\n",VERSION);
		return;
	}

	// Display ports statics
	if (strcmp(command, "show") == 0 && strcmp(param1, "ports") == 0)
	{
		int i;
		printf("\r\n-------------------------------------------------------------------------\r\n");
		for (i=0;i<4;i++)
		{

			printf("\r\nPort %d\r\n",i+1);
			if (port_status[i] == 1) printf(" Status: UP\r\n");
			if (port_status[i] == 0) printf(" Status: DOWN\r\n");
			for (int x=0;x<MAX_VLANS;x++)
			{
				if (Zodiac_Config.vlan_list[x].portmap[i] == 1)
				{
					if (Zodiac_Config.vlan_list[x].uVlanType == 0) printf(" VLAN type: Unassigned\r\n");
					if (Zodiac_Config.vlan_list[x].uVlanType == 1) printf(" VLAN type: OpenFlow\r\n");
					if (Zodiac_Config.vlan_list[x].uVlanType == 2) printf(" VLAN type: Native\r\n");
					printf(" VLAN ID: %d\r\n", Zodiac_Config.vlan_list[x].uVlanID);
				}
			}
			if( OF_Version == 1)
			{
				printf(" RX Bytes: %" PRIu64 "\r\n", phys10_port_stats[i].rx_bytes);
				printf(" TX Bytes: %" PRIu64 "\r\n", phys10_port_stats[i].tx_bytes);
				if (Zodiac_Config.of_port[i] == 1) printf(" RX Packets: %" PRIu64 "\r\n", phys10_port_stats[i].rx_packets);
				if (Zodiac_Config.of_port[i] == 1) printf(" TX Packets: %" PRIu64 "\r\n", phys10_port_stats[i].tx_packets);
				printf(" RX Dropped Packets: %" PRIu64 "\r\n", phys10_port_stats[i].rx_dropped);
				printf(" TX Dropped Packets: %" PRIu64 "\r\n", phys10_port_stats[i].tx_dropped);
				printf(" RX CRC Errors: %" PRIu64 "\r\n", phys10_port_stats[i].rx_crc_err);
			}
			if( OF_Version == 4)
			{
				printf(" RX Bytes: %" PRIu64 "\r\n", phys13_port_stats[i].rx_bytes);
				printf(" TX Bytes: %" PRIu64 "\r\n", phys13_port_stats[i].tx_bytes);
				if (Zodiac_Config.of_port[i] == 1) printf(" RX Packets: %" PRIu64 "\r\n", phys13_port_stats[i].rx_packets);
				if (Zodiac_Config.of_port[i] == 1) printf(" TX Packets: %" PRIu64 "\r\n", phys13_port_stats[i].tx_packets);
				printf(" RX Dropped Packets: %" PRIu64 "\r\n", phys13_port_stats[i].rx_dropped);
				printf(" TX Dropped Packets: %" PRIu64 "\r\n", phys13_port_stats[i].tx_dropped);
				printf(" RX CRC Errors: %" PRIu64 "\r\n", phys13_port_stats[i].rx_crc_err);
			}

		}
		printf("\r\n-------------------------------------------------------------------------\r\n\n");

		return;
	}

	// Display Config
	if (strcmp(command, "show")==0 && strcmp(param1, "status")==0){
		int hr = (totaltime/2)/3600;
		int t = (totaltime/2)%3600;
		int min = t/60;
		int sec = t%60;

		printf("\r\n-------------------------------------------------------------------------\r\n");
		printf("Device Status\r\n");
		printf(" CPU UID: %d-%d-%d-%d\r\n", uid_buf[0], uid_buf[1], uid_buf[2], uid_buf[3]);
		printf(" Firmware Version: %s\r\n",VERSION);
		printf(" CPU Temp: %d C\r\n", (int)ul_temp);
		printf(" Uptime: %02d:%02d:%02d", hr, min, sec);
		printf("\r\n-------------------------------------------------------------------------\r\n\n");
		return;
	}

	// Build shortcut - b XX:XX, where XX:XX are the last 4 digits of the new mac address
	if (strcmp(command, "b")==0)
	{
		uint8_t mac5,mac6;
		sscanf(param1, "%x:%x", &mac5, &mac6);
		Zodiac_Config.MAC_address[0] = 0x70;
		Zodiac_Config.MAC_address[1] = 0xb3;
		Zodiac_Config.MAC_address[2] = 0xd5;
		Zodiac_Config.MAC_address[3] = 0x6c;
		Zodiac_Config.MAC_address[4] = mac5;
		Zodiac_Config.MAC_address[5] = mac6;

		struct zodiac_config reset_config =
		{
			"Zodiac_FX",		// Name
			0,0,0,0,0,0,		// MAC Address
			10,0,1,99,			// IP Address
			255,255,255,0,		// Netmask
			10,0,1,1,			// Gateway Address
			10,0,1,8,			// IP Address of the SDN Controller
			6633,				// TCP port of SDN Controller
			1					// OpenFlow enabled
		};
		memset(&reset_config.vlan_list, 0, sizeof(struct virtlan)* MAX_VLANS); // Clear vlan array

		// Config VLAN 100
		sprintf(&reset_config.vlan_list[0].cVlanName, "OpenFlow");	// Vlan name
		reset_config.vlan_list[0].portmap[0] = 1;		// Assign port 1 to this vlan
		reset_config.vlan_list[0].portmap[1] = 1;		// Assign port 2 to this vlan
		reset_config.vlan_list[0].portmap[2] = 1;		// Assign port 3 to this vlan
		reset_config.vlan_list[0].uActive = 1;		// Vlan is active
		reset_config.vlan_list[0].uVlanID = 100;	// Vlan ID is 100
		reset_config.vlan_list[0].uVlanType = 1;	// Set as an Openflow Vlan
		reset_config.vlan_list[0].uTagged = 0;		// Set as untagged

		// Config VLAN 200
		sprintf(&reset_config.vlan_list[1].cVlanName, "Controller");
		reset_config.vlan_list[1].portmap[3] = 1;		// Assign port 4 to this vlan
		reset_config.vlan_list[1].uActive = 1;		// Vlan is active
		reset_config.vlan_list[1].uVlanID = 200;	// Vlan ID is 200
		reset_config.vlan_list[1].uVlanType = 2;	// Set as an Native Vlan
		reset_config.vlan_list[1].uTagged = 0;		// Set as untagged

		// Set ports
		reset_config.of_port[0] = 1;		// Port 1 is an OpenFlow port
		reset_config.of_port[1] = 1;		// Port 2 is an Openflow port
		reset_config.of_port[2] = 1;		// Port 3 is an OpenFlow port
		reset_config.of_port[3] = 2;		// Port 4 is an Native port

		// Failstate
		reset_config.failstate = 0;			// Failstate Secure
		
		// EtherType Filter
		reset_config.ethtype_filter = 0;		// Ethertype Filter Disabled

		// Force OpenFlow version
		reset_config.of_version = 0;			// Force version disabled

		memcpy(&reset_config.MAC_address, &Zodiac_Config.MAC_address, 6);		// Copy over existing MAC address so it is not reset
		memcpy(&Zodiac_Config, &reset_config, sizeof(struct zodiac_config));
		saveConfig();
		printf("Setup complete, MAC Address = %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n",Zodiac_Config.MAC_address[0], Zodiac_Config.MAC_address[1], Zodiac_Config.MAC_address[2], Zodiac_Config.MAC_address[3], Zodiac_Config.MAC_address[4], Zodiac_Config.MAC_address[5]);
		return;
	}

	// Restart switch	
	if (strcmp(command, "restart")==0)
	{
		printf("Restarting the Zodiac FX, please reopen your terminal application.\r\n");
		software_reset();
	}

	// Get CRC
	if (strcmp(command, "get")==0 && strcmp(param1, "crc")==0)
	{
		verification_check();
		printf("Calculated verification: %08x\r\n", verify.calculated);
		printf("Append [%08x 00000000] to the binary\r\n", ntohl(verify.calculated));
		return;
	}

	// Unknown Command
	printf("Unknown command\r\n");
	return;
}

/*
*	Commands within the config context
*
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void command_config(char *command, char *param1, char *param2, char *param3)
{
	// Return to root context
	if (strcmp(command, "exit")==0){
		uCLIContext = CLI_ROOT;
		return;
	}

	// Display help
	if (strcmp(command, "help") == 0)
	{
		printhelp();
		return;
	}

	// Load config
	if (strcmp(command, "load")==0){
		loadConfig();
		return;
	}

	// Save config
	if (strcmp(command, "save")==0){
		saveConfig();
		return;
	}

	// Restart switch
	if (strcmp(command, "restart")==0)
	{
		printf("Restarting the Zodiac FX, please reopen your terminal application.\r\n");
		software_reset();
	}
	
	// Display Config
	if (strcmp(command, "show")==0 && strcmp(param1, "config")==0){
		printf("\r\n-------------------------------------------------------------------------\r\n");
		printf("Configuration\r\n");
		printf(" Name: %s\r\n",Zodiac_Config.device_name);
		printf(" MAC Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n",Zodiac_Config.MAC_address[0], Zodiac_Config.MAC_address[1], Zodiac_Config.MAC_address[2], Zodiac_Config.MAC_address[3], Zodiac_Config.MAC_address[4], Zodiac_Config.MAC_address[5]);
		printf(" IP Address: %d.%d.%d.%d\r\n" , Zodiac_Config.IP_address[0], Zodiac_Config.IP_address[1], Zodiac_Config.IP_address[2], Zodiac_Config.IP_address[3]);
		printf(" Netmask: %d.%d.%d.%d\r\n" , Zodiac_Config.netmask[0], Zodiac_Config.netmask[1], Zodiac_Config.netmask[2], Zodiac_Config.netmask[3]);
		printf(" Gateway: %d.%d.%d.%d\r\n" , Zodiac_Config.gateway_address[0], Zodiac_Config.gateway_address[1], Zodiac_Config.gateway_address[2], Zodiac_Config.gateway_address[3]);
		printf(" OpenFlow Controller: %d.%d.%d.%d\r\n" , Zodiac_Config.OFIP_address[0], Zodiac_Config.OFIP_address[1], Zodiac_Config.OFIP_address[2], Zodiac_Config.OFIP_address[3]);
		printf(" OpenFlow Port: %d\r\n" , Zodiac_Config.OFPort);
		if (Zodiac_Config.OFEnabled == OF_ENABLED) printf(" Openflow Status: Enabled\r\n");
		if (Zodiac_Config.OFEnabled == OF_DISABLED) printf(" Openflow Status: Disabled\r\n");
		if (Zodiac_Config.failstate == 0) printf(" Failstate: Secure\r\n");
		if (Zodiac_Config.failstate == 1) printf(" Failstate: Safe\r\n");
		if (Zodiac_Config.of_version == 1) {
			printf(" Force OpenFlow version: 1.0 (0x01)\r\n");
		} else if (Zodiac_Config.of_version == 4){
			printf(" Force OpenFlow version: 1.3 (0x04)\r\n");
		} else {
			printf(" Force OpenFlow version: Disabled\r\n");
		}
		if (masterselect == true) printf(" Stacking Select: SLAVE\r\n");
		if (masterselect == false) printf(" Stacking Select: MASTER\r\n");
		if (stackenabled == true) printf(" Stacking Status: Enabled\r\n");
		if (stackenabled == false) printf(" Stacking Select: Disabled\r\n");
		if (Zodiac_Config.ethtype_filter == 1) printf(" EtherType Filtering: Enabled\r\n");
		if (Zodiac_Config.ethtype_filter != 1) printf(" EtherType Filtering: Disabled\r\n");
		printf("\r\n-------------------------------------------------------------------------\r\n\n");
		return;
	}

	// Display VLANs
	if (strcmp(command, "show")==0 && strcmp(param1, "vlans")==0){
		int x;
		printf("\r\n\tVLAN ID\t\tName\t\t\tType\r\n");
		printf("-------------------------------------------------------------------------\r\n");
		for (x=0;x<MAX_VLANS;x++)
		{
			if (Zodiac_Config.vlan_list[x].uActive == 1)
			{
				printf("\t%d\t\t'%s'\t\t",Zodiac_Config.vlan_list[x].uVlanID, Zodiac_Config.vlan_list[x].cVlanName);
				if (Zodiac_Config.vlan_list[x].uVlanType == 0) printf("Undefined\r\n");
				if (Zodiac_Config.vlan_list[x].uVlanType == 1) printf("OpenFlow\r\n");
				if (Zodiac_Config.vlan_list[x].uVlanType == 2) printf("Native\r\n");
			}
		}
		printf("\r\n-------------------------------------------------------------------------\r\n\n");
		return;
	}

//
//
// VLAN commands
//
//

	// Add new VLAN
	if (strcmp(command, "add")==0 && strcmp(param1, "vlan")==0)
	{
		int v;
		for(v=0;v<MAX_VLANS;v++)
		{
			if(Zodiac_Config.vlan_list[v].uActive != 1)
			{
				int namelen = strlen(param3);
				Zodiac_Config.vlan_list[v].uActive = 1;
				sscanf(param2, "%d", &Zodiac_Config.vlan_list[v].uVlanID);
				if (namelen > 15 ) namelen = 15; // Make sure name is less then 16 characters
				sprintf(Zodiac_Config.vlan_list[v].cVlanName, param3, namelen);
				printf("Added VLAN %d '%s'\r\n",Zodiac_Config.vlan_list[v].uVlanID, Zodiac_Config.vlan_list[v].cVlanName);
				return;
			}
		}
		// Can't find an empty VLAN slot
		printf("No more VLANs available\r\n");
		return;
	}

	// Delete an existing VLAN
	if (strcmp(command, "delete")==0 && strcmp(param1, "vlan")==0)
	{
		int vlanid;
		sscanf(param2, "%d", &vlanid);
		for (int x=0;x<MAX_VLANS;x++)
		{
			if(Zodiac_Config.vlan_list[x].uVlanID == vlanid)
			{
				Zodiac_Config.vlan_list[x].uActive = 0;
				Zodiac_Config.vlan_list[x].uVlanType = 0;
				Zodiac_Config.vlan_list[x].uTagged = 0;
				Zodiac_Config.vlan_list[x].uVlanID = 0;
				printf("VLAN %d deleted\r\n",vlanid);
				return;
			}
		}
			printf("Unknown VLAN ID\r\n");
			return;
	}

	// Set VLAN type
	if (strcmp(command, "set")==0 && strcmp(param1, "vlan-type")==0)
	{
		int vlanid;
		sscanf(param2, "%d", &vlanid);
		for (int x=0;x<MAX_VLANS;x++)
		{
			if(Zodiac_Config.vlan_list[x].uVlanID == vlanid)
			{
				if(strcmp(param3, "openflow")==0){
					Zodiac_Config.vlan_list[x].uVlanType = 1;
					printf("VLAN %d set as OpenFlow\r\n",vlanid);
					return;
				}
				if(strcmp(param3, "native")==0){
					Zodiac_Config.vlan_list[x].uVlanType = 2;
					printf("VLAN %d set as Native\r\n",vlanid);
					return;
				}
				printf("Unknown VLAN type\r\n");
				return;
			}
		}
			printf("Unknown VLAN ID\r\n");
			return;
	}

	// Add port to VLAN
	if (strcmp(command, "add")==0 && strcmp(param1, "vlan-port")==0)
	{
		int vlanid, port, x;
		sscanf(param2, "%d", &vlanid);
		sscanf(param3, "%d", &port);

		if (port < 1 || port > 4){
			printf("Invalid port number, ports are numbered 1 - 4\r\n");
			return;
		}

		// Check if the port is already assigned to a VLAN
		for (x=0;x<MAX_VLANS;x++){
			if(Zodiac_Config.vlan_list[x].portmap[port-1] == 1)
			{
				printf("Port %d is already assigned to VLAN %d\r\n", port, Zodiac_Config.vlan_list[x].uVlanID);
				return;
			}
		}

		// Assign the port to the requested VLAN
		for (x=0;x<MAX_VLANS;x++)
		{
			if(Zodiac_Config.vlan_list[x].uVlanID == vlanid)
			{
				if(Zodiac_Config.vlan_list[x].portmap[port-1] == 0  || Zodiac_Config.vlan_list[x].portmap[port-1] > 1 ){
					Zodiac_Config.vlan_list[x].portmap[port-1] = 1;
					Zodiac_Config.of_port[port-1] = Zodiac_Config.vlan_list[x].uVlanType;
					printf("Port %d is now assigned to VLAN %d\r\n", port, vlanid);
					return;
				}
			}
		}
			printf("Unknown VLAN ID\r\n");
			return;
	}

	// Delete a port from a VLAN
	if (strcmp(command, "delete")==0 && strcmp(param1, "vlan-port")==0)
	{
		int port, x;
		sscanf(param2, "%d", &port);

		if (port < 1 || port > 4){
			printf("Invalid port number, ports are numbered 1 - 4\r\n");
			return;
		}

		// Check if the port is already assigned to a VLAN
		for (x=0;x<MAX_VLANS;x++){
			if(Zodiac_Config.vlan_list[x].portmap[port-1] == 1)
			{
				Zodiac_Config.vlan_list[x].portmap[port-1] = 0;
				Zodiac_Config.of_port[port-1] = 0;
				printf("Port %d has been removed from VLAN %d\r\n", port, Zodiac_Config.vlan_list[x].uVlanID);
				return;
			}
		}
			printf("Port %d is not assigned to this VLAN\r\n",port);
			return;
	}

//
//
// Configuration commands
//
//

	// Set Device Name
	if (strcmp(command, "set")==0 && strcmp(param1, "name")==0)
	{
		uint8_t namelen = strlen(param2);
		if (namelen > 15 ) namelen = 15; // Make sure name is less then 16 characters
		sprintf(Zodiac_Config.device_name, param2, namelen);
		printf("Device name set to '%s'\r\n",Zodiac_Config.device_name);
		return;
	}

	// Set MAC Address
	if (strcmp(command, "set")==0 && strcmp(param1, "mac-address")==0)
	{
		int mac1,mac2,mac3,mac4,mac5,mac6;
		if (strlen(param2) != 17 )
		{
			printf("incorrect format\r\n");
			return;
		}
		sscanf(param2, "%x:%x:%x:%x:%x:%x", &mac1, &mac2, &mac3, &mac4, &mac5, &mac6);
		Zodiac_Config.MAC_address[0] = mac1;
		Zodiac_Config.MAC_address[1] = mac2;
		Zodiac_Config.MAC_address[2] = mac3;
		Zodiac_Config.MAC_address[3] = mac4;
		Zodiac_Config.MAC_address[4] = mac5;
		Zodiac_Config.MAC_address[5] = mac6;
		printf("MAC Address set to %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n",Zodiac_Config.MAC_address[0], Zodiac_Config.MAC_address[1], Zodiac_Config.MAC_address[2], Zodiac_Config.MAC_address[3], Zodiac_Config.MAC_address[4], Zodiac_Config.MAC_address[5]);
		return;
	}

	// Set IP Address
	if (strcmp(command, "set")==0 && strcmp(param1, "ip-address")==0)
	{
		int ip1,ip2,ip3,ip4;
		if (strlen(param2) > 15 )
		{
			printf("incorrect format\r");
			return;
		}
		sscanf(param2, "%d.%d.%d.%d", &ip1, &ip2,&ip3,&ip4);
		Zodiac_Config.IP_address[0] = ip1;
		Zodiac_Config.IP_address[1] = ip2;
		Zodiac_Config.IP_address[2] = ip3;
		Zodiac_Config.IP_address[3] = ip4;
		printf("IP Address set to %d.%d.%d.%d\r\n" , Zodiac_Config.IP_address[0], Zodiac_Config.IP_address[1], Zodiac_Config.IP_address[2], Zodiac_Config.IP_address[3]);
		return;
	}

	// Set Netmask Address
	if (strcmp(command, "set")==0 && strcmp(param1, "netmask")==0)
	{
		int nm1,nm2,nm3,nm4;
		if (strlen(param2) > 15 )
		{
			printf("incorrect format\r\n");
			return;
		}
		sscanf(param2, "%d.%d.%d.%d", &nm1, &nm2,&nm3,&nm4);
		Zodiac_Config.netmask[0] = nm1;
		Zodiac_Config.netmask[1] = nm2;
		Zodiac_Config.netmask[2] = nm3;
		Zodiac_Config.netmask[3] = nm4;
		printf("Netmask set to %d.%d.%d.%d\r\n" , Zodiac_Config.netmask[0], Zodiac_Config.netmask[1], Zodiac_Config.netmask[2], Zodiac_Config.netmask[3]);
		return;
	}

	// Set Gateway Address
	if (strcmp(command, "set")==0 && strcmp(param1, "gateway")==0)
	{
		int gw1,gw2,gw3,gw4;
		if (strlen(param2) > 15 )
		{
			printf("incorrect format\r\n");
			return;
		}
		sscanf(param2, "%d.%d.%d.%d", &gw1, &gw2,&gw3,&gw4);
		Zodiac_Config.gateway_address[0] = gw1;
		Zodiac_Config.gateway_address[1] = gw2;
		Zodiac_Config.gateway_address[2] = gw3;
		Zodiac_Config.gateway_address[3] = gw4;
		printf("Gateway set to %d.%d.%d.%d\r\n" , Zodiac_Config.gateway_address[0], Zodiac_Config.gateway_address[1], Zodiac_Config.gateway_address[2], Zodiac_Config.gateway_address[3]);
		return;
	}

	// Set OpenFlow Controller IP Address
	if (strcmp(command, "set")==0 && strcmp(param1, "of-controller")==0)
	{
		int oc1,oc2,oc3,oc4;
		if (strlen(param2) > 15 )
		{
			printf("incorrect format\r\n");
			return;
		}
		sscanf(param2, "%d.%d.%d.%d", &oc1,&oc2,&oc3,&oc4);
		Zodiac_Config.OFIP_address[0] = oc1;
		Zodiac_Config.OFIP_address[1] = oc2;
		Zodiac_Config.OFIP_address[2] = oc3;
		Zodiac_Config.OFIP_address[3] = oc4;
		printf("OpenFlow Server address set to %d.%d.%d.%d\r\n" , Zodiac_Config.OFIP_address[0], Zodiac_Config.OFIP_address[1], Zodiac_Config.OFIP_address[2], Zodiac_Config.OFIP_address[3]);
		return;
	}

	// Set OpenFlow Controller Port
	if (strcmp(command, "set")==0 && strcmp(param1, "of-port")==0)
	{
		sscanf(param2, "%d", &Zodiac_Config.OFPort);
		printf("OpenFlow Port set to %d\r\n" , Zodiac_Config.OFPort);
		return;
	}

	// Reset the device to a basic configuration
	if (strcmp(command, "factory")==0 && strcmp(param1, "reset")==0)
	{
		struct zodiac_config reset_config =
		{
			"Zodiac_FX",		// Name
			0,0,0,0,0,0,		// MAC Address
			10,0,1,99,			// IP Address
			255,255,255,0,		// Netmask
			10,0,1,1,			// Gateway Address
			10,0,1,8,			// IP Address of the SDN Controller
			6633,				// TCP port of SDN Controller
			1					// OpenFlow enabled
		};
		memset(&reset_config.vlan_list, 0, sizeof(struct virtlan)* MAX_VLANS); // Clear vlan array

		// Config VLAN 100
		sprintf(&reset_config.vlan_list[0].cVlanName, "Openflow");	// Vlan name
		reset_config.vlan_list[0].portmap[0] = 1;		// Assign port 1 to this vlan
		reset_config.vlan_list[0].portmap[1] = 1;		// Assign port 2 to this vlan
		reset_config.vlan_list[0].portmap[2] = 1;		// Assign port 3 to this vlan
		reset_config.vlan_list[0].uActive = 1;		// Vlan is active
		reset_config.vlan_list[0].uVlanID = 100;	// Vlan ID is 100
		reset_config.vlan_list[0].uVlanType = 1;	// Set as an Openflow Vlan
		reset_config.vlan_list[0].uTagged = 0;		// Set as untagged

		// Config VLAN 200
		sprintf(&reset_config.vlan_list[1].cVlanName, "Controller");
		reset_config.vlan_list[1].portmap[3] = 1;		// Assign port 4 to this vlan
		reset_config.vlan_list[1].uActive = 1;		// Vlan is active
		reset_config.vlan_list[1].uVlanID = 200;	// Vlan ID is 200
		reset_config.vlan_list[1].uVlanType = 2;	// Set as an Native Vlan
		reset_config.vlan_list[1].uTagged = 0;		// Set as untagged

		// Set ports
		reset_config.of_port[0] = 1;		// Port 1 is an OpenFlow port
		reset_config.of_port[1] = 1;		// Port 2 is an Openflow port
		reset_config.of_port[2] = 1;		// Port 3 is an OpenFlow port
		reset_config.of_port[3] = 2;		// Port 4 is an Native port

		// Failstate
		reset_config.failstate = 0;			// Failstate Secure

		// Force OpenFlow version
		reset_config.of_version = 0;			// Force version disabled

		memcpy(&reset_config.MAC_address, &Zodiac_Config.MAC_address, 6);		// Copy over existng MAC address so it is not reset
		memcpy(&Zodiac_Config, &reset_config, sizeof(struct zodiac_config));
		saveConfig();
		return;
	}

	// Set Failstate
	if (strcmp(command, "set")==0 && strcmp(param1, "failstate")==0)
	{
		if (strcmp(param2, "secure")==0){
			Zodiac_Config.failstate = 0;
			printf("Failstate set to Secure\r\n");
		} else if (strcmp(param2, "safe")==0){
			Zodiac_Config.failstate = 1;
			printf("Failstate set to Safe\r\n");
		} else {
			printf("Invalid failstate type\r\n");
		}
		return;
	}

	// Set Force OpenFlow Version
	if (strcmp(command, "set")==0 && strcmp(param1, "of-version")==0)
	{
		int tmp_version = -1;
		sscanf(param2, "%d", &tmp_version);
		if (tmp_version == 0){
				printf("Force OpenFlow version Disabled\r\n");
				Zodiac_Config.of_version = 0;
			} else if (tmp_version == 1){
				printf("Force OpenFlow version set to 1.0 (0x01)\r\n");
				Zodiac_Config.of_version = 1;
			} else if (tmp_version == 4){
				printf("Force OpenFlow version set to 1.3 (0x04)\r\n");
				Zodiac_Config.of_version = 4;
			} else {
				printf("Invalid OpenFlow version, valid options are 0, 1 or 4\r\n");
				Zodiac_Config.of_version = 0;
		}
		return;
	}

	// Enable EtherType filtering
	if (strcmp(command, "set")==0 && strcmp(param1, "ethertype-filter")==0)
	{
		if (strcmp(param2, "disable")==0){
			Zodiac_Config.ethtype_filter = 0;
			printf("EtherType Filtering Disabled\r\n");
			} else if (strcmp(param2, "enable")==0){
			Zodiac_Config.ethtype_filter = 1;
			printf("EtherType Filtering Enabled\r\n");
			} else {
			printf("Invalid value\r\n");
		}
		return;
	}
	
	// Unknown Command
	printf("Unknown command\r\n");
	return;
}

/*
*	Commands within the OpenFlow context
*
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void command_openflow(char *command, char *param1, char *param2, char *param3)
{
	if (strcmp(command, "exit")==0){
		uCLIContext = CLI_ROOT;
		return;
	}

	// Display help
	if (strcmp(command, "help") == 0)
	{
		printhelp();
		return;

	}

	// Openflow Flows
	if (strcmp(command, "show") == 0 && strcmp(param1, "flows") == 0)
	{
		int i;
		struct ofp_action_header * act_hdr;
		if (iLastFlow > 0)
		{
			// OpenFlow v1.0 (0x01) Flow Table
			if( OF_Version == 1)
			{
				printf("\r\n-------------------------------------------------------------------------\r\n");
				for (i=0;i<iLastFlow;i++)
				{
					printf("\r\nFlow %d\r\n",i+1);
					printf(" Match:\r\n");
					printf("  Incoming Port: %d\t\t\tEthernet Type: 0x%.4X\r\n",ntohs(flow_match10[i]->match.in_port), ntohs(flow_match10[i]->match.dl_type));
					printf("  Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\t\tDestination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n",flow_match10[i]->match.dl_src[0], flow_match10[i]->match.dl_src[1], flow_match10[i]->match.dl_src[2], flow_match10[i]->match.dl_src[3], flow_match10[i]->match.dl_src[4], flow_match10[i]->match.dl_src[5] \
					, flow_match10[i]->match.dl_dst[0], flow_match10[i]->match.dl_dst[1], flow_match10[i]->match.dl_dst[2], flow_match10[i]->match.dl_dst[3], flow_match10[i]->match.dl_dst[4], flow_match10[i]->match.dl_dst[5]);
					if (ntohs(flow_match10[i]->match.dl_vlan) == 0xffff)
					{
						printf("  VLAN ID: N/A\t\t\t\tVLAN Priority: N/A\r\n");
					} else {
						printf("  VLAN ID: %d\t\t\t\tVLAN Priority: 0x%x\r\n",ntohs(flow_match10[i]->match.dl_vlan), flow_match10[i]->match.dl_vlan_pcp);
					}
					if ((ntohs(flow_match10[i]->match.dl_type) == 0x0800) || (ntohs(flow_match10[i]->match.dl_type) == 0x8100)) printf("  IP Protocol: %d\t\t\tIP ToS Bits: 0x%.2X\r\n",flow_match10[i]->match.nw_proto, flow_match10[i]->match.nw_tos);
					if (flow_match10[i]->match.nw_proto == 7 || flow_match10[i]->match.nw_proto == 16)
					{
						printf("  TCP Source Address: %d.%d.%d.%d\r\n",ip4_addr1(&flow_match10[i]->match.nw_src), ip4_addr2(&flow_match10[i]->match.nw_src), ip4_addr3(&flow_match10[i]->match.nw_src), ip4_addr4(&flow_match10[i]->match.nw_src));
						printf("  TCP Destination Address: %d.%d.%d.%d\r\n", ip4_addr1(&flow_match10[i]->match.nw_dst), ip4_addr2(&flow_match10[i]->match.nw_dst), ip4_addr3(&flow_match10[i]->match.nw_dst), ip4_addr4(&flow_match10[i]->match.nw_dst));
						printf("  TCP/UDP Source Port: %d\t\tTCP/UDP Destination Port: %d\r\n",ntohs(flow_match10[i]->match.tp_src), ntohs(flow_match10[i]->match.tp_dst));
					}
					if (flow_match10[i]->match.nw_proto == 1)
					{
						printf("  ICMP Type: %d\t\t\t\tICMP Code: %d\r\n",ntohs(flow_match10[i]->match.tp_src), ntohs(flow_match10[i]->match.tp_dst));
					}
					printf("  Wildcards: 0x%.8x\t\t\tCookie: 0x%" PRIx64 "\r\n",ntohl(flow_match10[i]->match.wildcards), htonll(flow_match10[i]->cookie));
					printf("\r Attributes:\r\n");
					printf("  Priority: %d\t\t\tDuration: %d secs\r\n",ntohs(flow_match10[i]->priority), (totaltime/2) - flow_counters[i].duration);
					printf("  Hard Timeout: %d secs\t\t\tIdle Timeout: %d secs\r\n",ntohs(flow_match10[i]->hard_timeout), ntohs(flow_match10[i]->idle_timeout));
					printf("  Byte Count: %d\t\t\tPacket Count: %d\r\n",flow_counters[i].bytes, flow_counters[i].hitCount);
					printf("\r\n Actions:\r\n");
					for(int q=0;q<4;q++)
					{
						if(q == 0) act_hdr = flow_actions10[i]->action1;
						if(q == 1) act_hdr = flow_actions10[i]->action2;
						if(q == 2) act_hdr = flow_actions10[i]->action3;
						if(q == 3) act_hdr = flow_actions10[i]->action4;

						if(act_hdr->len == 0 && q == 0) printf("   DROP\r\n"); // No actions = DROP

						if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_OUTPUT) // Output to port action
						{
							struct ofp_action_output * action_out = act_hdr;
							printf("  Action %d:\r\n",q+1);
							if (ntohs(action_out->port) <= 255) printf("   Output: %d\r\n", ntohs(action_out->port));
							if (ntohs(action_out->port) == OFPP_IN_PORT) printf("   Output: IN_PORT\r\n");
							if (ntohs(action_out->port) == OFPP_FLOOD) printf("   Output: FLOOD\r\n");
							if (ntohs(action_out->port) == OFPP_ALL) printf("   Output: ALL\r\n");
							if (ntohs(action_out->port) == OFPP_CONTROLLER) printf("   Output: CONTROLLER\r\n");
						}
						if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_SET_VLAN_VID) //
						{
							struct ofp_action_vlan_vid *action_vlanid = act_hdr;
							printf("  Action %d:\r\n",q+1);
							printf("   Set VLAN ID: %d\r\n", ntohs(action_vlanid->vlan_vid));
						}

						if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_SET_DL_DST) //
						{
							struct ofp_action_dl_addr *action_setdl = act_hdr;
							printf("  Action %d:\r\n",q+1);
							printf("   Set Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", action_setdl->dl_addr[0],action_setdl->dl_addr[1],action_setdl->dl_addr[2],action_setdl->dl_addr[3],action_setdl->dl_addr[4],action_setdl->dl_addr[5]);
						}
						if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_SET_DL_SRC) //
						{
							struct ofp_action_dl_addr *action_setdl = act_hdr;
							printf("  Action %d:\r\n",q+1);
							printf("   Set Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", action_setdl->dl_addr[0],action_setdl->dl_addr[1],action_setdl->dl_addr[2],action_setdl->dl_addr[3],action_setdl->dl_addr[4],action_setdl->dl_addr[5]);
						}
						if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_STRIP_VLAN) //
						{
							printf("  Action %d:\r\n",q+1);
							printf("   Strip VLAN tag\r\n");
						}
					}
				}
				printf("\r\n-------------------------------------------------------------------------\r\n\n");
			}
			// OpenFlow v1.3 (0x04) Flow Table
			if( OF_Version == 4)
			{
				int match_size;
				int inst_size;
				int act_size;
				struct ofp13_instruction_actions *inst_actions;
				struct oxm_header13 oxm_header;
				uint8_t oxm_value8;
				uint16_t oxm_value16;
				uint32_t oxm_value32;
				uint8_t oxm_eth[6];
				uint8_t oxm_ipv4[4];
				uint16_t oxm_ipv6[8];

				printf("\r\n-------------------------------------------------------------------------\r\n");
				for (i=0;i<iLastFlow;i++)
				{
					printf("\r\nFlow %d\r\n",i+1);
					printf(" Match:\r\n");
					match_size = 0;

					while (match_size < (ntohs(flow_match13[i]->match.length)-4))
					{
						memcpy(&oxm_header, ofp13_oxm_match[i] + match_size,4);
						bool has_mask = oxm_header.oxm_field & 1;
						oxm_header.oxm_field = oxm_header.oxm_field >> 1;
						switch(oxm_header.oxm_field)
						{
							case OFPXMT_OFB_IN_PORT:
							memcpy(&oxm_value32, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 4);
							printf("  In Port: %d\r\n",ntohl(oxm_value32));
							break;

							case OFPXMT_OFB_ETH_DST:
							memcpy(&oxm_eth, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 6);
							printf("  Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
							break;

							case OFPXMT_OFB_ETH_SRC:
							memcpy(&oxm_eth, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 6);
							printf("  Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
							break;

							case OFPXMT_OFB_ETH_TYPE:
							memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
							if (ntohs(oxm_value16) == 0x0806)printf("  ETH Type: ARP\r\n");
							if (ntohs(oxm_value16) == 0x0800)printf("  ETH Type: IPv4\r\n");
							if (ntohs(oxm_value16) == 0x86dd)printf("  ETH Type: IPv6\r\n");
							if (ntohs(oxm_value16) == 0x8100)printf("  ETH Type: VLAN\r\n");
							break;

							case OFPXMT_OFB_IP_PROTO:
							memcpy(&oxm_value8, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 1);
							if (oxm_value8 == 1)printf("  IP Protocol: ICMP\r\n");
							if (oxm_value8 == 6)printf("  IP Protocol: TCP\r\n");
							if (oxm_value8 == 17)printf("  IP Protocol: UDP\r\n");
							break;

							case OFPXMT_OFB_IPV4_SRC:
							if (has_mask)
							{
								memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 8);
								printf("  Source IP:  %d.%d.%d.%d / %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3], oxm_ipv4[4], oxm_ipv4[5], oxm_ipv4[6], oxm_ipv4[7]);
								} else {
								memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 4);
								printf("  Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
							}
							break;

							case OFPXMT_OFB_IPV4_DST:
							if (has_mask)
							{
								memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 8);
								printf("  Destination IP:  %d.%d.%d.%d / %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3], oxm_ipv4[4], oxm_ipv4[5], oxm_ipv4[6], oxm_ipv4[7]);
							} else {
								memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 4);
								printf("  Destination IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
							}
							break;

							case OFPXMT_OFB_IPV6_SRC:
							memcpy(&oxm_ipv6, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 16);
							printf("  Source IP: %.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X\r\n", oxm_ipv6[0], oxm_ipv6[1], oxm_ipv6[2], oxm_ipv6[3], oxm_ipv6[4], oxm_ipv6[5], oxm_ipv6[6], oxm_ipv6[7]);
							break;

							case OFPXMT_OFB_IPV6_DST:
							memcpy(&oxm_ipv6, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 16);
							printf("  Destination IP:  %.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X\r\n", oxm_ipv6[0], oxm_ipv6[1], oxm_ipv6[2], oxm_ipv6[3], oxm_ipv6[4], oxm_ipv6[5], oxm_ipv6[6], oxm_ipv6[7]);
							break;

							case OFPXMT_OFB_TCP_SRC:
							memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
							printf("  Source TCP Port: %d\r\n",ntohs(oxm_value16));
							break;

							case OFPXMT_OFB_TCP_DST:
							memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
							printf("  Destination TCP Port: %d\r\n",ntohs(oxm_value16));
							break;

							case OFPXMT_OFB_UDP_SRC:
							memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
							printf("  Source UDP Port: %d\r\n",ntohs(oxm_value16));
							break;

							case OFPXMT_OFB_UDP_DST:
							memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
							printf("  Destination UDP Port: %d\r\n",ntohs(oxm_value16));
							break;

							case OFPXMT_OFB_VLAN_VID:
							memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
							if (oxm_value16 != 0) printf("  VLAN ID: %d\r\n",(ntohs(oxm_value16) - OFPVID_PRESENT));
							break;

						};
						match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					}
					printf("\r Attributes:\r\n");
					printf("  Table ID: %d\t\t\t\tCookie:0x%" PRIx64 "\r\n",flow_match13[i]->table_id, htonll(flow_match13[i]->cookie));
					printf("  Priority: %d\t\t\t\tDuration: %d secs\r\n",ntohs(flow_match13[i]->priority), (totaltime/2) - flow_counters[i].duration);
					printf("  Hard Timeout: %d secs\t\t\tIdle Timeout: %d secs\r\n",ntohs(flow_match13[i]->hard_timeout), ntohs(flow_match13[i]->idle_timeout));
					printf("  Byte Count: %d\t\t\tPacket Count: %d\r\n",flow_counters[i].bytes, flow_counters[i].hitCount);
					int lm = (totaltime/2) - flow_counters[i].lastmatch;
					int hr = lm/3600;
					int t = lm%3600;
					int min = t/60;
					int sec = t%60;
					printf("  Last Match: %02d:%02d:%02d\r\n", hr, min, sec);
					
					// Print instruction list
					if (ofp13_oxm_inst[i] != NULL)
					{
						// Get a list of all instructions for this flow
						void *insts[8] = {0};
						inst_size = 0;
						while(inst_size < ofp13_oxm_inst_size[i]){
							struct ofp13_instruction *inst_ptr = (struct ofp13_instruction *)(ofp13_oxm_inst[i] + inst_size);
							insts[ntohs(inst_ptr->type)] = inst_ptr;
							inst_size += ntohs(inst_ptr->len);
						}
						
						printf("\r Instructions:\r\n");
						
						// Check for optional metering instruction
						if(insts[OFPIT13_METER] != NULL)						
						{
							struct ofp13_instruction_meter *inst_meter = insts[OFPIT13_METER];
							printf("  Meter: %d\r\n", ntohl(inst_meter->meter_id));
						}
						
						if(insts[OFPIT13_APPLY_ACTIONS] != NULL)
						{
							printf("  Apply Actions:\r\n");
							struct ofp13_action_header *act_hdr;
							act_size = 0;
							inst_actions = insts[OFPIT13_APPLY_ACTIONS];
							if (ntohs(inst_actions->len) == sizeof(struct ofp13_instruction_actions)) printf("   DROP \r\n");	// No actions
							while (act_size < (ntohs(inst_actions->len) - sizeof(struct ofp13_instruction_actions)))
							{
								act_hdr = (struct ofp13_action_header*)((uintptr_t)inst_actions->actions + act_size);
								if (htons(act_hdr->type) == OFPAT13_OUTPUT)
								{
									struct ofp13_action_output *act_output = act_hdr;
									if (htonl(act_output->port) < OFPP13_MAX)
									{
										printf("   Output Port: %d\r\n", htonl(act_output->port));
									} else if (htonl(act_output->port) == OFPP13_IN_PORT)
									{
										printf("   Output: IN_PORT \r\n");
									} else if (htonl(act_output->port) == OFPP13_FLOOD)
									{
										printf("   Output: FLOOD \r\n");
									} else if (htonl(act_output->port) == OFPP13_ALL)
									{
										printf("   Output: ALL \r\n");
									} else if (htonl(act_output->port) == OFPP13_CONTROLLER)
									{
										printf("   Output: CONTROLLER \r\n");
									}
									act_output = NULL;
								}

								if (htons(act_hdr->type) == OFPAT13_SET_FIELD)
								{
									struct ofp13_action_set_field *act_set_field = act_hdr;
									memcpy(&oxm_header, act_set_field->field,4);
									oxm_header.oxm_field = oxm_header.oxm_field >> 1;
									switch(oxm_header.oxm_field)
									{
										case OFPXMT_OFB_VLAN_VID:
										memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
										printf("   Set VLAN ID: %d\r\n",(ntohs(oxm_value16) - OFPVID_PRESENT));
										break;

										case OFPXMT_OFB_ETH_SRC:
										memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
										printf("   Set Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
										break;

										case OFPXMT_OFB_ETH_DST:
										memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
										printf("   Set Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
										break;

										case OFPXMT_OFB_ETH_TYPE:
										memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
										if (ntohs(oxm_value16) == 0x0806 )printf("   Set ETH Type: ARP\r\n");
										if (ntohs(oxm_value16) == 0x0800 )printf("   Set ETH Type: IPv4\r\n");
										if (ntohs(oxm_value16) == 0x86dd )printf("   Set ETH Type: IPv6\r\n");
										if (ntohs(oxm_value16) == 0x8100 )printf("   Set ETH Type: VLAN\r\n");
										break;

										case OFPXMT_OFB_IPV4_SRC:
										memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
										printf("   Set Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
										break;

										case OFPXMT_OFB_IP_PROTO:
										memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
										if (oxm_value16 == 1)printf("   Set IP Protocol: ICMP\r\n");
										if (oxm_value16 == 6)printf("   Set IP Protocol: TCP\r\n");
										if (oxm_value16 == 17)printf("   Set IP Protocol: UDP\r\n");
										break;

										case OFPXMT_OFB_IPV4_DST:
										memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
										printf("   Set Destination IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
										break;

										case OFPXMT_OFB_TCP_SRC:
										memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
										printf("   Set TCP Source Port:  %d\r\n", ntohs(oxm_value16));
										break;

										case OFPXMT_OFB_TCP_DST:
										memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
										printf("   Set TCP Destination Port:  %d\r\n", ntohs(oxm_value16));
										break;

										case OFPXMT_OFB_UDP_SRC:
										memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
										printf("   Set UDP Source Port:  %d\r\n", ntohs(oxm_value16));
										break;

										case OFPXMT_OFB_UDP_DST:
										memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
										printf("   Set UDP Destination Port:  %d\r\n", ntohs(oxm_value16));
										break;

										case OFPXMT_OFB_ICMPV4_TYPE:
										memcpy(&oxm_value8, act_set_field->field + sizeof(struct oxm_header13), 1);
										printf("   Set ICMP Type:  %d\r\n", oxm_value8);
										break;

										case OFPXMT_OFB_ICMPV4_CODE:
										memcpy(&oxm_value8, act_set_field->field + sizeof(struct oxm_header13), 1);
										printf("   Set ICMP Code:  %d\r\n", oxm_value8);
										break;

										case OFPXMT_OFB_ARP_OP:
										memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
										printf("   Set ARP OP Code:  %d\r\n", ntohs(oxm_value16));
										break;

										case OFPXMT_OFB_ARP_SPA:
										memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
										printf("   Set ARP Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
										break;

										case OFPXMT_OFB_ARP_TPA:
										memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
										printf("   Set ARP Target IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
										break;

										case OFPXMT_OFB_ARP_SHA:
										memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
										printf("   Set ARP Source HA: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
										break;

										case OFPXMT_OFB_ARP_THA:
										memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
										printf("   Set ARP Target HA: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
										break;

									};
								}

								if (htons(act_hdr->type) == OFPAT13_PUSH_VLAN)
								{
									struct ofp13_action_push *act_push = act_hdr;
									printf("   Push VLAN tag\r\n");
								}

								if (htons(act_hdr->type) == OFPAT13_POP_VLAN)
								{
									printf("   Pop VLAN tag\r\n");
								}

								act_size += htons(act_hdr->len);
							}
						}
						// Print goto table instruction
						if(insts[OFPIT13_GOTO_TABLE] != NULL)
						{
							struct ofp13_instruction_goto_table *inst_goto_ptr;
							inst_goto_ptr = (struct ofp13_instruction_goto_table *) insts[OFPIT13_GOTO_TABLE];
							printf("  Goto Table: %d\r\n", inst_goto_ptr->table_id);
						}
					} else {
						// No instructions
						printf("\r Instructions:\r\n");
						printf("   DROP \r\n");
					}
				}
				printf("\r\n-------------------------------------------------------------------------\r\n\n");
			}
		} else {
			printf("No Flows installed!\r\n");
		}
		return;
	}

	// List tables
	if (strcmp(command, "show") == 0 && strcmp(param1, "tables") == 0)
	{
		if( OF_Version == 1)
		{
			printf("\r\n-------------------------------------------------------------------------\r\n");
			if(iLastFlow > 0)
			{
				printf("Table: 0\r\n");
				printf(" Flows: %d\r\n",iLastFlow);
				printf(" Lookups: %d\r\n",table_counters[0].lookup_count);
				printf(" Matches: %d\r\n",table_counters[0].matched_count);
				printf(" Bytes: %d\r\n",table_counters[0].byte_count);
				printf("\r\n");
			} else printf("No Flows.\r\n");
			printf("-------------------------------------------------------------------------\r\n");
		}

		if( OF_Version == 4)
		{
			int flow_count;
			printf("\r\n-------------------------------------------------------------------------\r\n");
			for (int x=0;x<MAX_TABLES;x++)
			{
				flow_count = 0;
				for (int i=0;i<iLastFlow;i++)
				{
					if(flow_match13[i]->table_id == x)
					{
						flow_count++;
					}
				}
				if(flow_count > 0)
				{
					printf("Table: %d\r\n",x);
					printf(" Flows: %d\r\n",flow_count);
					printf(" Lookups: %d\r\n",table_counters[x].lookup_count);
					printf(" Matches: %d\r\n",table_counters[x].matched_count);
					printf(" Bytes: %d\r\n",table_counters[x].byte_count);
					printf("\r\n");
				}
			}
			printf("-------------------------------------------------------------------------\r\n");
		}
		return;
	}

	// Openflow status
	if (strcmp(command, "show") == 0 && strcmp(param1, "status") == 0)
	{
		printf("\r\n-------------------------------------------------------------------------\r\n");
		printf("OpenFlow Status\r");
		if (tcp_pcb->state != ESTABLISHED && Zodiac_Config.OFEnabled == OF_ENABLED) printf(" Status: Disconnected\r\n");
		if (tcp_pcb->state == ESTABLISHED && Zodiac_Config.OFEnabled == OF_ENABLED) printf(" Status: Connected\r\n");
		if (Zodiac_Config.OFEnabled == OF_DISABLED) printf(" Status: Disabled\r\n");
		if (OF_Version == 1)
		{
			printf(" Version: 1.0 (0x01)\r\n");
			printf(" No tables: 1\r\n");
			printf(" No flows: %d\r\n", iLastFlow);
			printf(" Total Lookups: %d\r\n",table_counters[0].lookup_count);
			printf(" Total Matches: %d\r\n",table_counters[0].matched_count);
		}
		if (OF_Version == 4)
		{
			int flow_count;
			int tables = 0;
			for (int x=0;x<MAX_TABLES;x++)
			{
				flow_count = 0;
				for (int i=0;i<iLastFlow;i++)
				{
					if(flow_match13[i]->table_id == x)
					{
						flow_count++;
					}
				}
				if(flow_count > 0) tables++;
			}
			printf(" Version: 1.3 (0x04)\r\n");
			printf(" No tables: %d\r\n", tables);
			printf(" No flows: %d\r\n", iLastFlow);
			// Total up all the table stats
			int lookup_count = 0;
			int matched_count = 0;
			for (int x=0;x<MAX_TABLES;x++)
			{
				lookup_count += table_counters[x].lookup_count;
				matched_count += table_counters[x].matched_count;
			}
			printf(" Total Lookups: %d\r\n",lookup_count);
			printf(" Total Matches: %d\r\n",matched_count);
		}
		printf("\r\n-------------------------------------------------------------------------\r\n");
		return;
	}

	// Enable OpenFlow
	if (strcmp(command, "enable")==0)
	{

		Zodiac_Config.OFEnabled = OF_ENABLED;
		enableOF();
		printf("Openflow Enabled\r\n");
		return;
	}

	// Disable OpenFlow
	if (strcmp(command, "disable")==0)
	{
		Zodiac_Config.OFEnabled = OF_DISABLED;
		disableOF();
		printf("Openflow Disabled\r\n");
		return;
	}

	// Clear the flow table
	if (strcmp(command, "clear")==0 && strcmp(param1, "flows")==0)
	{
		printf("Clearing flow table, %d flow deleted.\r\n", iLastFlow);
		clear_flows();
		return;
	}
	
	// Show meter table entries
	if (strcmp(command, "show") == 0 && strcmp(param1, "meters") == 0)
	{
		int meter_out_counter = 1;
		
		// Check that table is populated
		if(meter_entry[0] != NULL)
		{
			int meter_index = 0;
			while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
			{
					printf("\r\n-------------------------------------------------------------------------\r\n");
					printf("\r\nMeter %d\r\n", meter_out_counter);
					meter_out_counter++;
					printf("  Meter ID: %d\r\n", meter_entry[meter_index]->meter_id);
					printf("  Counters:\r\n");
					meter_entry[meter_index]->flow_count = get_bound_flows(meter_entry[meter_index]->meter_id);
					printf("\tBound Flows:\t%d\tDuration:\t%d sec\r\n", meter_entry[meter_index]->flow_count, (sys_get_ms()-meter_entry[meter_index]->time_added)/1000);
					printf("\tByte Count:\t%"PRIu64"\tPacket Count:\t%"PRIu64"\r\n", meter_entry[meter_index]->byte_in_count, meter_entry[meter_index]->packet_in_count);
					printf("\tConfiguration:\t");
					if(((meter_entry[meter_index]->flags) & OFPMF13_KBPS) == OFPMF13_KBPS)
					{
						printf("KBPS; ");
					}
					if(((meter_entry[meter_index]->flags) & OFPMF13_PKTPS) == OFPMF13_PKTPS)
					{
						printf("PKTPS; ");
					}
					if(((meter_entry[meter_index]->flags) & OFPMF13_BURST) == OFPMF13_BURST)
					{
						printf("BURST; ");
					}
					if(((meter_entry[meter_index]->flags) & OFPMF13_STATS) == OFPMF13_STATS)
					{
						printf("STATS; ");
					}
					if(meter_entry[meter_index]->flags == 0)
					{
						printf(" NONE;");
					}
					
					printf("\r\n\tNumber of bands:\t%d\r\n", meter_entry[meter_index]->band_count);
					int bands_processed = 0;
					struct ofp13_meter_band_drop * ptr_band;
					ptr_band = &(meter_entry[meter_index]->bands);
					while(bands_processed < meter_entry[meter_index]->band_count)
					{
						printf("\t\tBand %d:\r\n", bands_processed+1);
						printf("\t\t  Type:\t\t");
						if(ptr_band->type == OFPMBT13_DROP)
						{
							printf("DROP\r\n");
						}
						else if(ptr_band->type == OFPMBT13_DSCP_REMARK)
						{
							printf("DSCP REMARK (unsupported)\r\n");
						}
						else
						{
							printf("unsupported type\r\n");
						}
						printf("\t\t  Rate:\t\t%d\t\r\n", ptr_band->rate);
						printf("\t\t  Burst Size:\t%d\t\r\n", ptr_band->burst_size);
						
						// Find band index
						int band_index = ((uint8_t*)ptr_band - (uint8_t*)&(meter_entry[meter_index]->bands)) / sizeof(struct ofp13_meter_band_drop);
						
						// Display counters
						printf("\t\t  Byte count:\t%"PRIu64"\t\r\n", band_stats_array[meter_index].band_stats[band_index].byte_band_count);
						printf("\t\t  Packet count:\t%"PRIu64"\t\r\n", band_stats_array[meter_index].band_stats[band_index].packet_band_count);
						
						ptr_band++;	// Move to next band
						bands_processed++;
					}
				meter_index++;
			}
			printf("\r\n-------------------------------------------------------------------------\r\n\r\n");
		}
		else
		{
			printf("No meters configured.\r\n");
		}
		return;
	}
	// Unknown Command
	printf("Unknown command\r\n");
	return;
}

/*
*	Commands within the debug context
*
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void command_debug(char *command, char *param1, char *param2, char *param3)
{
	if (strcmp(command, "exit")==0){
		uCLIContext = CLI_ROOT;
		return;
	}

	// Display help
	if (strcmp(command, "help") == 0)
	{
		printhelp();
		return;

	}

	if (strcmp(command, "read")==0)
	{
		int n = switch_read(atoi(param1));
		printf("Register %d = 0x%.2X\r\n\n", atoi(param1), n);
		return;
	}

	if (strcmp(command, "write")==0)
	{
		int n = switch_write(atoi(param1),atoi(param2));
		printf("Register %d = 0x%.2X\r\n\n", atoi(param1),n);
		return;
	}

	if (strcmp(command, "spi")==0)
	{
		//stack_write(atoi(param1));
		return;
	}

	if (strcmp(command, "mem")==0)
	{
		printf("mem total: %d\r\n", membag_get_total());
		printf("mem free: %d\r\n", membag_get_total_free());
		printf("Smallest available block: %d\r\n", membag_get_smallest_free_block_size());
		printf("Largest available block: %d\r\n", membag_get_largest_free_block_size());		
		return;
	}

	if (strcmp(command, "trace")==0)
	{
		trace = true;
		printf("Starting trace...\r\n");
		return;
	}	
	
	// Unknown Command response
	printf("Unknown command\r\n");
	return;
}
/*
*	Print the intro screen
*	ASCII art generated from http://patorjk.com/software/taag/
*
*/
void printintro(void)
{
	printf("\r\n");
	printf(" _____             ___               _______  __\r\n");
	printf("/__  /  ____  ____/ (_)___ ______   / ____/ |/ /\r\n");
	printf("  / /  / __ \\/ __  / / __ `/ ___/  / /_   |   /\r\n");
	printf(" / /__/ /_/ / /_/ / / /_/ / /__   / __/  /   |  \r\n");
	printf("/____/\\____/\\__,_/_/\\__,_/\\___/  /_/    /_/|_| \r\n");
	printf("\t    by Northbound Networks\r\n");
	printf("\r\n\n");
	printf("Type 'help' for a list of available commands\r\n");
	return;
}

/*
*	Print a list of available commands
*
*
*/
void printhelp(void)
{
	printf("\r\n");
	printf("The following commands are currently available:\r\n");
	printf("\r\n");
	printf("Base:\r\n");
	printf(" config\r\n");
	printf(" openflow\r\n");
	printf(" debug\r\n");
	printf(" update\r\n");
	printf(" show status\r\n");
	printf(" show version\r\n");
	printf(" show ports\r\n");
	printf(" restart\r\n");
	printf(" help\r\n");
	printf("\r\n");
	printf("Config:\r\n");
	printf(" save\r\n");
	printf(" restart\r\n");
	printf(" show config\r\n");
	printf(" show vlans\r\n");
	printf(" set name <name>\r\n");
	printf(" set mac-address <mac address>\r\n");
	printf(" set ip-address <ip address>\r\n");
	printf(" set netmask <netmasks>\r\n");
	printf(" set gateway <gateway ip address>\r\n");
	printf(" set of-controller <openflow controller ip address>\r\n");
	printf(" set of-port <openflow controller tcp port>\r\n");
	printf(" set failstate <secure|safe>\r\n");
	printf(" add vlan <vlan id> <vlan name>\r\n");
	printf(" delete vlan <vlan id>\r\n");
	printf(" set vlan-type <vlan id> <openflow|native>\r\n");
	printf(" add vlan-port <vlan id> <port>\r\n");
	printf(" delete vlan-port <port>\r\n");
	printf(" set of-version <version(0|1|4)>\r\n");
	printf(" set ethertype-filter <enable|disable>\r\n");
	printf(" factory reset\r\n");
	printf(" exit\r\n");
	printf("\r\n");
	printf("OpenFlow:\r\n");
	printf(" show status\r\n");
	printf(" show tables\r\n");
	printf(" show flows\r\n");
	printf(" show meters\r\n");
	printf(" enable\r\n");
	printf(" disable\r\n");
	printf(" clear flows\r\n");
	printf(" exit\r\n");
	printf("\r\n");
	printf("Debug:\r\n");
	printf(" read <register>\r\n");
	printf(" write <register> <value>\r\n");
	printf(" mem\r\n");
	printf(" trace\r\n");
	printf(" exit\r\n");
	printf("\r\n");
	return;
}
