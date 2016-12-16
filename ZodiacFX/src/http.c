/**
 * @file
 * http.c
 *
 * This file contains the http functions
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
#include <string.h>
#include <inttypes.h>
#include "http.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "timers.h"
#include "command.h"
#include "trace.h"
#include "config_zodiac.h"
#include "openflow/openflow.h"
#include "eeprom.h"
#include "flash.h"
#include "switch.h"

// External Variables
extern int totaltime;
extern int32_t ul_temp;
extern struct zodiac_config Zodiac_Config;
extern uint8_t port_status[4];
extern uint32_t uid_buf[4];	// Unique identifier
extern struct tcp_pcb *tcp_pcb;
extern int OF_Version;

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

// Local Variables
struct tcp_pcb *http_pcb;
char http_msg[64];			// Buffer for HTTP message filtering
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];	// SHARED_BUFFER_LEN must never be reduced below 2048

static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t http_accept(void *arg, struct tcp_pcb *pcb, err_t err);
void http_send(char *buffer, struct tcp_pcb *pcb, bool out);

uint8_t interfaceCreate_Frames(void);
uint8_t interfaceCreate_Header(void);
uint8_t interfaceCreate_Menu(void);
uint8_t interfaceCreate_Home(void);
uint8_t interfaceCreate_Display_Home(void);
uint8_t interfaceCreate_Display_Ports(uint8_t step);
uint8_t interfaceCreate_Display_OpenFlow(void);
uint8_t interfaceCreate_Display_Flows(void);
uint8_t interfaceCreate_Config_Home(void);
uint8_t interfaceCreate_Config_Network(void);
uint8_t interfaceCreate_Config_VLANs(void);
uint8_t interfaceCreate_Config_OpenFlow(void);
uint8_t interfaceCreate_About(void);

bool reset_required;

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
*	HTTP initialization function
*
*/
void http_init(void)
{
	http_pcb = tcp_new();
	tcp_bind(http_pcb, IP_ADDR_ANY, 80);
	http_pcb = tcp_listen(http_pcb);
	tcp_accept(http_pcb, http_accept);
}

/*
*	HTTP accept function
*
*/
static err_t http_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	LWIP_UNUSED_ARG(arg);
	LWIP_UNUSED_ARG(err);
	tcp_setprio(pcb, TCP_PRIO_NORMAL);
	tcp_recv(pcb, http_recv);
	tcp_err(pcb, NULL);
	tcp_poll(pcb, NULL, 4);
	return ERR_OK;
}

/*
*	HTTP receive function
*
*/
static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	int len;
	int i = 0;
	char *http_payload;
	char *pdat;
	memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
	
	if (err == ERR_OK && p != NULL)
	{
		tcp_recved(pcb, p->tot_len);
		http_payload = (char*)p->payload;
		len = p->tot_len;
		
		// Check HTTP method
		i = 0;
		while(i < 63 && (http_payload[i] != ' '))
		{
			http_msg[i] = http_payload[i];
			i++;
		}
		TRACE("http.c: %s method received", http_msg);
	
		if(strcmp(http_msg,"GET") == 0)
		{			
			memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
			
			// Specified resource directly follows GET
			i = 0;
			while(i < 63 && (http_payload[i+5] != ' '))
			{
				http_msg[i] = http_payload[i+5];	// Offset http_payload to isolate resource
				i++;
			}
			
			if(http_msg[0] == '\0')
			{			
				TRACE("http.c: resource request for page frames");
			}
			else
			{
				TRACE("http.c: resource request for %s", http_msg);
			}
			
			// Check resource & serve page
			if(http_msg[0] == '\0')
			{
				if(interfaceCreate_Frames())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"header.htm") == 0)
			{
				if(interfaceCreate_Header())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"menu.htm") == 0)
			{
				if(interfaceCreate_Menu())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"home.htm") == 0)
			{
				if(interfaceCreate_Home())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
      		else if(strcmp(http_msg,"d_home.htm") == 0)
			{
				if(interfaceCreate_Display_Home())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"d_ports.htm") == 0)
			{
				if(interfaceCreate_Display_Ports(0))
				{
					// Only write to buffer - don't send
					http_send(&shared_buffer, pcb, 0);
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
					
				if(interfaceCreate_Display_Ports(1))
				{
					// Call TCP output & close the connection
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
      		else if(strcmp(http_msg,"d_of.htm") == 0)
			{
				if(interfaceCreate_Display_OpenFlow())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
      		else if(strcmp(http_msg,"d_flo.htm") == 0)
			{
				if(interfaceCreate_Display_Flows())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
      		else if(strcmp(http_msg,"cfg_home.htm") == 0)
			{
				if(interfaceCreate_Config_Home())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
      		else if(strcmp(http_msg,"cfg_net.htm") == 0)
			{
				if(interfaceCreate_Config_Network())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
      		else if(strcmp(http_msg,"cfg_vlan.htm") == 0)
			{
				if(interfaceCreate_Config_VLANs())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"cfg_of.htm") == 0)
			{
				if(interfaceCreate_Config_OpenFlow())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"about.htm") == 0)
			{
				if(interfaceCreate_About())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else
			{
				TRACE("http.c: resource doesn't exist:\"%s\"", http_msg);
			}
		}
		else if(strcmp(http_msg,"POST") == 0)
		{
			memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array

			// Specified resource directly follows POST
			i = 0;
			while(i < 63 && (http_payload[i+6] != ' '))
			{
				http_msg[i] = http_payload[i+6];	// Offset http_payload to isolate resource
				i++;
			}
						
			TRACE("http.c: request for %s", http_msg);
			
			if(strcmp(http_msg,"save_config") == 0)
			{
				memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
				
				// Device Name
				pdat = strstr(http_payload, "wi_deviceName");	// Search for element
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_deviceName")+1);	// Data format: wi_deviceName=(name)
					
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')	// Check that the next parameter directly follows the "&" at end of data
					{
						uint8_t namelen = strlen(http_msg);
						if (namelen > 15 ) namelen = 15; // Make sure name is less than 16 characters
						sprintf(Zodiac_Config.device_name, http_msg, namelen);
						TRACE("http.c: device name set to '%s'",Zodiac_Config.device_name);
					}
					else
					{
						TRACE("http.c: \"&\" cannot be used in device name");
					}
				}
				else
				{
					TRACE("http.c: no device name found");
				}
				
				memset(&http_msg, 0, sizeof(http_msg));
								
				// MAC Address
				pdat = strstr(http_payload, "wi_macAddress");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_macAddress")+1);	// Data format: wi_deviceName=(name)
					
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
						int mac1,mac2,mac3,mac4,mac5,mac6;
						char decArr[18] = "";
						int j, k;
						
						if (strlen(http_msg) != 27 )	// Accounting for ":" as "%3A"
						{
							TRACE("http.c: incorrect MAC address format");
							return;
						}
						
						// Decode http string
						j = 0; k = 0;
						while(j < strlen(http_msg) && k < 18)
						{
							if(http_msg[j] == '%' && http_msg[j+1] == '3' && http_msg[j+2] == 'A')
							{
								decArr[k] = ':';
								j+=3; k++;
							}
							else
							{
								decArr[k] = http_msg[j];
								j++; k++;
							}
						}
						
						sscanf(decArr, "%x:%x:%x:%x:%x:%x", &mac1, &mac2, &mac3, &mac4, &mac5, &mac6);
						Zodiac_Config.MAC_address[0] = mac1;
						Zodiac_Config.MAC_address[1] = mac2;
						Zodiac_Config.MAC_address[2] = mac3;
						Zodiac_Config.MAC_address[3] = mac4;
						Zodiac_Config.MAC_address[4] = mac5;
						Zodiac_Config.MAC_address[5] = mac6;
						TRACE("http.c: MAC address set to %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",Zodiac_Config.MAC_address[0], Zodiac_Config.MAC_address[1], Zodiac_Config.MAC_address[2], Zodiac_Config.MAC_address[3], Zodiac_Config.MAC_address[4], Zodiac_Config.MAC_address[5]);
					}
					else
					{
						TRACE("http.c: \"&\" cannot be used in form");
					}
				}
				else
				{
					TRACE("http.c: no MAC address found");
				}
				
				memset(&http_msg, 0, sizeof(http_msg));
								
				// IP Address
				pdat = strstr(http_payload, "wi_ipAddress");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_ipAddress")+1);	// Data format: wi_deviceName=(name)
									
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
						int ip1,ip2,ip3,ip4;
						if (strlen(http_msg) > 15 )
						{
							TRACE("http.c: incorrect IP format");
							return;
						}
						sscanf(http_msg, "%d.%d.%d.%d", &ip1, &ip2,&ip3,&ip4);
						Zodiac_Config.IP_address[0] = ip1;
						Zodiac_Config.IP_address[1] = ip2;
						Zodiac_Config.IP_address[2] = ip3;
						Zodiac_Config.IP_address[3] = ip4;
						TRACE("http.c: IP address set to %d.%d.%d.%d" , Zodiac_Config.IP_address[0], Zodiac_Config.IP_address[1], Zodiac_Config.IP_address[2], Zodiac_Config.IP_address[3]);
					}
					else
					{
						TRACE("http.c: \"&\" cannot be used in form");
					}
				}
				else
				{
					TRACE("http.c: no IP address found");
				}
		
				memset(&http_msg, 0, sizeof(http_msg));
								
				// Netmask
				pdat = strstr(http_payload, "wi_netmask");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_netmask")+1);	// Data format: wi_deviceName=(name)
									
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
						int nm1,nm2,nm3,nm4;
						if (strlen(http_msg) > 15 )
						{
							TRACE("http.c: incorrect netmask format");
							return;
						}
						sscanf(http_msg, "%d.%d.%d.%d", &nm1, &nm2,&nm3,&nm4);
						Zodiac_Config.netmask[0] = nm1;
						Zodiac_Config.netmask[1] = nm2;
						Zodiac_Config.netmask[2] = nm3;
						Zodiac_Config.netmask[3] = nm4;
						TRACE("http.c: netmask set to %d.%d.%d.%d" , Zodiac_Config.netmask[0], Zodiac_Config.netmask[1], Zodiac_Config.netmask[2], Zodiac_Config.netmask[3]);				
					}
					else
					{
						TRACE("http.c: \"&\" cannot be used in form");
					}
				}
				else
				{
					TRACE("http.c: no netmask found");
				}
				
				memset(&http_msg, 0, sizeof(http_msg));
							
				// Gateway	
				pdat = strstr(http_payload, "wi_gateway");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_gateway")+1);	// Data format: wi_deviceName=(name)
									
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					
					// No next 'w' character check as this is the last element
					
					int gw1,gw2,gw3,gw4;
					if (strlen(http_msg) > 15 )
					{
						TRACE("http.c: incorrect gateway format");
						return;
					}
					sscanf(http_msg, "%d.%d.%d.%d", &gw1, &gw2,&gw3,&gw4);
					Zodiac_Config.gateway_address[0] = gw1;
					Zodiac_Config.gateway_address[1] = gw2;
					Zodiac_Config.gateway_address[2] = gw3;
					Zodiac_Config.gateway_address[3] = gw4;
					TRACE("http.c: gateway set to %d.%d.%d.%d" , Zodiac_Config.gateway_address[0], Zodiac_Config.gateway_address[1], Zodiac_Config.gateway_address[2], Zodiac_Config.gateway_address[3]);
				}
				else
				{
					TRACE("http.c: no gateway address found");
				}
				
				// Save configuration to EEPROM
				eeprom_write();
				TRACE("http.c: config written to EEPROM");
				
				// Set update required flag
				reset_required = true;
				
				// Send updated config page
				if(interfaceCreate_Config_Network())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: updated page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
				}
								
				// Send updated header page (with restart button)
				
					// ***** Placeholder until frame refresh targeting is implemented
					//
					//
					//
					
			}
			else if(strcmp(http_msg,"btn_restart") == 0)
			{
				TRACE("http.c: restarting the Zodiac FX. Please reconnect.");
				for(int x = 0;x<100000;x++);	// Let the above message get sent to the terminal before detaching
				udc_detach();	// Detach the USB device before restart
				rstc_start_software_reset(RSTC);	// Software reset
				while (1);
			}
			else if(strcmp(http_msg,"btn_default") == 0)
			{
				TRACE("http.c: restoring factory settings");
				
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

				// Force OpenFlow version
				reset_config.of_version = 0;			// Force version disabled

				memcpy(&reset_config.MAC_address, &Zodiac_Config.MAC_address, 6);		// Copy over existing MAC address so it is not reset
				memcpy(&Zodiac_Config, &reset_config, sizeof(struct zodiac_config));
				eeprom_write();
				
				TRACE("http.c: restarting the Zodiac FX. Please reconnect.");
				for(int x = 0;x<100000;x++);	// Let the above message get sent to the terminal before detaching
				udc_detach();	// Detach the USB device before restart
				rstc_start_software_reset(RSTC);	// Software reset
				while (1);
			}
			else if(strcmp(http_msg,"save_ports") == 0)
			{
				// Save VLAN port associations
				
				memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
				int port = 0;
				int x, y;
				int vlanid;
				char portID[10];
				
				// Search for "wi_pxID"
				for (x=0;x<MAX_VLANS;x++)
				{
					port = x+1;
					snprintf(portID, 10, "wi_p%dID=", port);
					pdat = strstr(http_payload, portID);	// Search for element
					if(pdat != NULL)	// Check that the element exists
					{
						pdat += (strlen(portID));	// Data format: wi_p1ID=(VLAN ID)
					
						i = 0;
						while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
						{
							http_msg[i] = pdat[i];	// Store value of element
							i++;
						}
						
						vlanid = atoi(http_msg);
						
						if(vlanid == 0)
						{
							// Not a valid selection
							
							//for (y=0;y<MAX_VLANS;y++)
							//{
								//// User wants to disassociate the VLAN with the port
								//if(Zodiac_Config.vlan_list[y].portmap[port-1] == 1)
								//{
									//Zodiac_Config.vlan_list[y].portmap[port-1] = 0;
									//Zodiac_Config.of_port[port-1] = 0;
									//TRACE("http.c: port %d has been removed from VLAN %d", port, Zodiac_Config.vlan_list[y].uVlanID);
								//}
							//}
						}
						else
						{
							// User wants to change the port VLAN
							// Delete previous assigned VLAN
							for (y=0;y<MAX_VLANS;y++)
							{
								// User wants to disassociate the VLAN with the port
								if(Zodiac_Config.vlan_list[y].portmap[port-1] == 1)
								{
									Zodiac_Config.vlan_list[y].portmap[port-1] = 0;
									Zodiac_Config.of_port[port-1] = 0;
									TRACE("http.c: port %d has been removed from VLAN %d", port, Zodiac_Config.vlan_list[y].uVlanID);
								}
							}

							// Assign the port to the requested VLAN
							for (y=0;y<MAX_VLANS;y++)
							{
								if(Zodiac_Config.vlan_list[y].uVlanID == vlanid)
								{
									if(Zodiac_Config.vlan_list[y].portmap[port-1] == 0  || Zodiac_Config.vlan_list[x].portmap[port-1] > 1 )
									{
										Zodiac_Config.vlan_list[y].portmap[port-1] = 1;
										Zodiac_Config.of_port[port-1] = Zodiac_Config.vlan_list[y].uVlanType;
										TRACE("http.c: port %d is now assigned to VLAN %d", port, vlanid);
									}
								}
							}
						}
					}
					else
					{
						TRACE("http.c: port VLAN ID not found in Display: Ports response")
					}
				}
				
				// Save configuration to EEPROM
				eeprom_write();
				TRACE("http.c: config written to EEPROM");
				
				// Send updated page
				if(interfaceCreate_Display_Ports(0))
				{
					// Only write to buffer - don't send
					http_send(&shared_buffer, pcb, 0);
					TRACE("http.c: updated ports page sent successfully (1/2) - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
				}
				
				if(interfaceCreate_Display_Ports(1))
				{
					// Call TCP output & close the connection
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: updated ports page sent successfully (2/2) - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"btn_ofNext") == 0)
			{
				
			}
			else if(strcmp(http_msg,"btn_ofPrev") == 0)
			{
				
			}
			else if(strcmp(http_msg,"btn_ofClear") == 0)
			{
				// Clear the flow table
				TRACE("http.c: clearing flow table, %d flow deleted.\r\n", iLastFlow);
				clear_flows();

				// Send updated page
				if(interfaceCreate_Display_Flows())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: updated page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"save_vlan") == 0)
			{
				memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
				
				// Search for btn=
				pdat = strstr(http_payload, "btn=");	// Search for element
				if(pdat != NULL)	// Check that the element exists
				{
					pdat += (strlen("btn="));	// Data format: btn=btn_name
					
					i = 0;
					while(i < 7)	// VLAN button can only be "btn_add" or "btn_del"
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
				}
				else
				{
					TRACE("http.c: button not found in Config: VLANs response")
				}

				// Match pressed button
				if(strcmp(http_msg,"btn_del") == 0)
				{
					int num = -1;
					pdat += (strlen("btn_del"));	// Data format: btn=btn_del[number]
					
					num = pdat[0] - '0';	// Convert single char element to int
					
					TRACE("http.c: deleting element %d in vlan list", num);
					
					// Table row must be mapped to the ACTIVE VLANs
					i = 0;				// for stepping through the vlan list
					uint8_t ctr = 0;	// for mapping active items & checking against desired delete
					uint8_t done = 0;	// Break once the correct element is found
					while(i >= 0 && i < MAX_VLANS && !done)
					{
						// Check if vlan is active
						if(Zodiac_Config.vlan_list[i].uActive == 1)
						{
							// Check if this is the element to be deleted
							if(ctr == num)
							{
								// Delete existing VLAN
								Zodiac_Config.vlan_list[i].uActive = 0;
								Zodiac_Config.vlan_list[i].uVlanType = 0;
								Zodiac_Config.vlan_list[i].uTagged = 0;
								Zodiac_Config.vlan_list[i].uVlanID = 0;
								done = 1;
							}
							else
							{
								ctr++;
							}
						}
						i++;
					}
				}
				else if(strcmp(http_msg,"btn_add") == 0)
				{
					int vlID = 0;
					char vlName[16] = "";
					int vlType = 0;
					
					// Find ID input	
					memset(&http_msg, 0, sizeof(http_msg));		
					pdat = strstr(http_payload, "wi_vlID");
					if(pdat != NULL)	// Check that element exists
					{
						pdat += (strlen("wi_vlID")+1);	// Data format: wi_vlID=(ID)
					
						i = 0;
						while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
						{
							http_msg[i] = pdat[i];	// Store value of element
							i++;
						}
						if(pdat[i+1] == 'w' && strlen(http_msg))	// Check to make sure data follows
						{
							vlID = atoi(http_msg);
							TRACE("http.c: VLAN ID: %d", vlID);
						}
						else
						{
							TRACE("http.c: invalid VLAN ID input");
						}
					}
					else
					{
						TRACE("http.c: no VLAN ID found");
					}
				
					// Find VLAN name input
					pdat = strstr(http_payload, "wi_vlName");
					if(pdat != NULL)	// Check that element exists
					{
						pdat += (strlen("wi_vlName")+1);	// Data format: wi_vlName=(Name)
					
						i = 0;
						while(i < 15 && (pdat[i] != '&'))
						{
							vlName[i] = pdat[i];	// Store value of element
							i++;
						}
						if(pdat[i+1] == 'w' && strlen(vlName))	// Check to make sure data follows
						{
							TRACE("http.c: VLAN Name: %s", vlName);
						}
						else
						{
							TRACE("http.c: invalid VLAN Name input");
						}
					}
					else
					{
						TRACE("http.c: no VLAN Name found");
					}
					
					// Find VLAN type input	
					pdat = strstr(http_payload, "wi_vlType");
					if(pdat != NULL)	// Check that element exists
					{
						pdat += (strlen("wi_vlType")+1);	// Data format: wi_vlType=(Type)
						vlType = pdat[0] - '0';		// Convert single char element to int
					}
					else
					{
						TRACE("http.c: no VLAN Type found");
					}
					
					// Add new VLAN
					int v=0;
					uint8_t done = 0;
					while(v < MAX_VLANS && !done)
					{
						if(Zodiac_Config.vlan_list[v].uActive != 1)
						{
							Zodiac_Config.vlan_list[v].uActive = 1;
							Zodiac_Config.vlan_list[v].uVlanID = vlID;
							sprintf(Zodiac_Config.vlan_list[v].cVlanName, vlName, strlen(vlName));
							Zodiac_Config.vlan_list[v].uVlanType = vlType;
							TRACE("http.c: added VLAN %d '%s', type %d",Zodiac_Config.vlan_list[v].uVlanID, Zodiac_Config.vlan_list[v].cVlanName, Zodiac_Config.vlan_list[v].uVlanType);
							done = 1;
						}
						v++;
					}
					if(!done)
					{
						TRACE("http.c: maximum VLAN limit reached");
					}
				}
				else
				{
					TRACE("http.c: unhandled button in Config: VLANs")
				}
				
				// Save configuration to EEPROM
				eeprom_write();
				TRACE("http.c: config written to EEPROM");
				
				// Send updated config page
				if(interfaceCreate_Config_VLANs())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: updated page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else if(strcmp(http_msg,"save_of") == 0)
			{
				// Controller IP Address
				memset(&http_msg, 0, sizeof(http_msg));
				pdat = strstr(http_payload, "wi_ofIP");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_ofIP")+1);	// Data format: wi_ofIP=(IP)
									
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
						int oc1,oc2,oc3,oc4;
						if (strlen(http_msg) > 15 )
						{
							TRACE("http.c: incorrect IP format");
							return;
						}
						sscanf(http_msg, "%d.%d.%d.%d", &oc1,&oc2,&oc3,&oc4);
						Zodiac_Config.OFIP_address[0] = oc1;
						Zodiac_Config.OFIP_address[1] = oc2;
						Zodiac_Config.OFIP_address[2] = oc3;
						Zodiac_Config.OFIP_address[3] = oc4;
						TRACE("http.c: openflow server address set to %d.%d.%d.%d" ,\
							Zodiac_Config.OFIP_address[0], Zodiac_Config.OFIP_address[1],\
							Zodiac_Config.OFIP_address[2], Zodiac_Config.OFIP_address[3]\
								);
					}
					else
					{
						TRACE("http.c: \"&\" cannot be used in form");
					}
				}
				
				// Controller Port
				memset(&http_msg, 0, sizeof(http_msg));
				pdat = strstr(http_payload, "wi_ofPort");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_ofPort")+1);	// Data format: wi_ofPort=(Port)
					
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
						Zodiac_Config.OFPort = atoi(http_msg);
						TRACE("OpenFlow Port set to %d" , Zodiac_Config.OFPort);
					}
					else
					{
						TRACE("http.c: \"&\" cannot be used in form");
					}
				}
				
				// OpenFlow Status
				memset(&http_msg, 0, sizeof(http_msg));
				pdat = strstr(http_payload, "wi_ofStatus");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_ofStatus")+1);	// Data format: wi_ofPort=(Port)
					
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					
					if(strcmp(http_msg,"Enable") == 0)
					{
						Zodiac_Config.OFEnabled = OF_ENABLED;
						enableOF();
						TRACE("http.c: openflow enabled");
					}
					else if(strcmp(http_msg,"Disable") == 0)
					{
						Zodiac_Config.OFEnabled = OF_DISABLED;
						disableOF();
						TRACE("http.c: openflow disabled");
					}
					else
					{
						TRACE("http.c: unhandled openflow status");
					}
				}
				
				// OpenFlow Status
				pdat = strstr(http_payload, "wi_failstate");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_failstate")+1);	// Data format: wi_failstate=(state)
					
					int failstate = 0;
					failstate = pdat[0] - '0';	// Convert single char element to int
					
					if(failstate == 0)
					{
						Zodiac_Config.failstate = 0;
						TRACE("http.c: failstate set to Secure (0)");
					}
					else if(failstate == 1)
					{
						Zodiac_Config.failstate = 1;
						TRACE("http.c: failstate set to Safe (1)");
					}
					else
					{
						TRACE("http.c: unhandled failstate");
					}
				}
				
				// OpenFlow Force Version
				pdat = strstr(http_payload, "wi_ofVer");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("wi_ofVer")+1);	// Data format: wi_ofVer=(version)
					
					int forceVer = 0;
					forceVer = pdat[0] - '0';	// Convert single char element to int
					
					if(forceVer == 0)
					{
						Zodiac_Config.of_version = 0;
						TRACE("http.c: force openflow version set to auto (0)");
					}
					else if(forceVer == 1)
					{
						Zodiac_Config.of_version = 1;
						TRACE("http.c: force openflow version set to 1.0 (1)");
					}
					else if(forceVer == 4)
					{
						Zodiac_Config.of_version = 4;
						TRACE("http.c: force openflow version set to 1.3 (4)");
					}
					else
					{
						TRACE("http.c: unhandled openflow version");
					}
				}
				
				// Save configuration to EEPROM
				eeprom_write();
				TRACE("http.c: config written to EEPROM");
				
				// Send updated config page
				if(interfaceCreate_Config_OpenFlow())
				{
					http_send(&shared_buffer, pcb, 1);
					TRACE("http.c: updated page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
			else
			{
				TRACE("http.c: unknown request: \"%s\"", http_msg);
			}
		}
		else
		{
			TRACE("http.c: WARNING: unknown HTTP method received");
		}
				
	}

	pbuf_free(p);

	if (err == ERR_OK && p == NULL)
	{
		TRACE("http.c: Closing TCP connection.");
		tcp_close(pcb);
	}

	return ERR_OK;
}

/*
*	HTTP Send function
*
*	Parameter:
*		out - specify whether TCP packet should be sent
*/
void http_send(char *buffer, struct tcp_pcb *pcb, bool out)
{
	uint16_t len = strlen(buffer);
	err_t err;
	uint16_t buf_size;
		
	buf_size = tcp_sndbuf(pcb);
	
	// Check available tcp buffer space
	if(len < buf_size)
	{
		// Write data to tcp buffer
		err = tcp_write(pcb, buffer, len, TCP_WRITE_FLAG_COPY + TCP_WRITE_FLAG_MORE);
		TRACE("http.c: sending %d bytes to TCP stack, %d REMAINING in buffer", len, (buf_size - len));

		// Check if more data needs to be written
		if(out == true)
		{
			TRACE("http.c: calling tcp_output & closing connection");
			if (err == ERR_OK) tcp_output(pcb);
			tcp_close(pcb);
		}
	}
	
	return;
}

/*
*	Create and format HTTP/HTML for frames
*
*/
uint8_t interfaceCreate_Frames(void)
{
	// Format HTTP response
	sprintf(shared_buffer,"HTTP/1.1 200 OK\r\n");
	strcat(shared_buffer,"Connection: close\r\n");
	strcat(shared_buffer,"Content-Type: text/html; charset=UTF-8\r\n\r\n");
	// Send frames
	strcat(shared_buffer, \
			"<!DOCTYPE html>"\
			"<html>"\
				"<head>"\
					"<title>Zodiac FX</title>"\
				"</head>"\
				"<frameset rows=\"75,*\">"\
					"<frame src=\"header.htm\" name=\"titleframe\" noresize scrolling=\"no\" frameborder=\"1\">"\
					"<frameset cols=\"160, *\">"\
						"<frameset rows=\"*,0\">"\
						"<frame src=\"menu.htm\" name=\"sidebar\" noresize scrolling=\"no\" frameborder=\"1\">"\
						"</frameset>"\
						"<frame src=\"home.htm\" name=\"page\" scrolling=\"auto\" frameborder=\"1\">"\
					"</frameset>"\
					"<noframes>"\
						"<body>"\
						"<p>Browser version not supported."\
						"</body>"\
					"</noframes>"\
				"</frameset>"\
			"</html>"\
				);
	TRACE("http.c: html written to buffer");

	if(strlen(shared_buffer) < 2048)
	{
		TRACE("http.c: http/html written to buffer");
		return 1;
	}
	else
	{
		// This should never occur, as the page is of a known size.
		TRACE("http.c: ERROR: frame page buffer overflow");
		return 0;
	}
}

/*
*	Create and format HTML for header
*
*/
uint8_t interfaceCreate_Header(void)
{
	reset_required = true;	// ***** Placeholder until frame refresh targeting is implemented
	
	int hr = (totaltime/2)/3600;
	int t = (totaltime/2)%3600;
	int min = t/60;

	// Send header
	if(reset_required == false)
	{
		if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
				"<!DOCTYPE html>"\
				"<META http-equiv=\"refresh\" content=\"61\">"\
				"<html>"\
					"<head>"\
					"<style>"\
						"header {"\
							"font-family:Sans-serif;"\
							"position: absolute;"\
							"top: 0;"\
							"left: 0;"\
							"width: 100%%;"\
							"height: 100%%;"\
							"overflow: hidden;"\
							"color: white;"\
							"background: black;"\
						"}"\
						"h1 {"\
							"margin-top:20px;"\
							"padding-left: 20px;"\
						"}"\
                		".info {"\
							"font-family:Sans-serif;"\
							"color: white;"\
							"position: fixed;"\
							"right: 150px;"\
							"top: 30px;"\
						"}"\
					"</style>"\
					"</head>"\
					"<body>"\
						"<header>"\
							"<h1>Zodiac FX</h1>"\
						"</header>"\
                		"<div class=\"info\">"\
							"Uptime: %02d:%02d"\
						"</div>"\
					"</body>"\
				"</html>"\
					, hr, min) < SHARED_BUFFER_LEN)
		{
			TRACE("http.c: html written to buffer");
			return 1;
		}
		else
		{
			TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
			return 0;
		}
	}
	else if(reset_required == true)
	{
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
			"<!DOCTYPE html>"\
			"<META http-equiv=\"refresh\" content=\"61\">"\
			"<html>"\
				"<head>"\
				"<style>"\
					"header {"\
						"font-family:Sans-serif;"\
						"position: absolute;"\
						"top: 0;"\
						"left: 0;"\
						"width: 100%%;"\
						"height: 100%%;"\
						"overflow: hidden;"\
						"color: white;"\
						"background: black;"\
					"}"\
					"h1 {"\
						"margin-top:20px;"\
						"padding-left: 20px;"\
					"}"\
					".wrapper {"\
						"text-align: right;"\
					"}"\
					"button {"\
						"position: relative;"\
						"top: 20px;"\
						"right: 20px;"\
					"}"\
                	".info {"\
						"font-family:Sans-serif;"\
						"color: white;"\
						"position: fixed;"\
						"right: 150px;"\
						"top: 30px;"\
					"}"\
				"</style>"\
				"</head>"\
				"<body>"\
					"<header>"\
						"<h1>Zodiac FX</h1>"\
					"</header>"\
					"<div class=\"wrapper\">"\
						"<form action=\"btn_restart\" method=\"post\"  onsubmit=\"return confirm('Zodiac FX will now restart. This may take up to 30 seconds');\">"\
							"<button name=\"btn\" value=\"btn_restart\">Restart</button>"\
						"</form>"\
					"</div>"\
                	"<div class=\"info\">"\
						"Uptime: %02d:%02d"\
					"</div>"\
				"</body>"\
			"</html>"\
				, hr, min) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}
}

/*
*	Create and format HTML for menu page
*
*/
uint8_t interfaceCreate_Menu(void)
{
	// Send menu
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
				"body {"\
					"font-family:Sans-serif;"\
					"line-height: 1.9em;"\
					"font-size: 20px;"\
					"font-weight: bold;"\
					"background: #F6F6F6;"\
				"}"\
				"body ul {"\
					"list-style-type: none;"\
					"margin: 10px;"\
					"padding: 0;"\
				"}"\
				"body ul a {"\
					"color: black;"\
					"text-decoration: none;"\
				"}"\
				"body ul a:active {"\
					"font-weight: 700;"\
				"}"\
				"#sub {"\
					"font-size: 15px;"\
					"margin-left: 10px;"\
					"line-height: 1.7em;"\
				"}"\
				"</style>"\
			"</head>"\
				"<body>"\
					"<ul>"\
						"<li><a href=\"home.htm\" target=\"page\">Status</a></li>"\
						"<li><a href=\"d_home.htm\" target=\"page\">Display</a></li>"\
						"<li id=\"sub\"><a href=\"d_ports.htm\" target=\"page\">Ports</a></li>"\
						"<li id=\"sub\"><a href=\"d_of.htm\" target=\"page\">OpenFlow</a></li>"\
						"<li id=\"sub\"><a href=\"d_flo.htm\" target=\"page\">Flows</a></li>"\
						"<li><a href=\"cfg_home.htm\" target=\"page\">Config</a></li>"\
						"<li id=\"sub\"><a href=\"cfg_net.htm\" target=\"page\">Network</a></li>"\
						"<li id=\"sub\"><a href=\"cfg_vlan.htm\" target=\"page\">VLANs</a></li>"\
						"<li id=\"sub\"><a href=\"cfg_of.htm\" target=\"page\">OpenFlow</a></li>"\
						"<li><a href=\"about.htm\" target=\"page\">About</a></li>"\
					"</ul>"\
				"</body>"\
		"</html>"\
				) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}

/*
*	Create and format HTML for home page
*
*/
uint8_t interfaceCreate_Home(void)
{	
	int hr = (totaltime/2)/3600;
	int t = (totaltime/2)%3600;
	int min = t/60;

	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<META http-equiv=\"refresh\" content=\"61\">"\
		"<html>"\
			"<head>"\
				"<style>"\
				"body {"\
					"overflow: auto;"\
					"font-family:Sans-serif;"\
					"line-height: 1.2em;"\
					"font-size: 17px;"\
					"margin-left: 20px;"\
				"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<h2>Status</h2>"\
				"<p>"\
					"CPU UID: %d-%d-%d-%d<br>"\
					"Firmware Version: %s<br>"\
					"CPU Temp: %d C<br>"\
					"Uptime: %02d:%02d"\
				"</p>"\
				"<form action=\"btn_default\" method=\"post\"  onsubmit=\"return confirm('Zodiac FX will be reset to factory settings. Do you wish to proceed?');\">"\
					"<button name=\"btn\" value=\"btn_default\">Factory Reset</button>"\
				"</form>"\
			"</body>"\
		"</html>"\
				, uid_buf[0], uid_buf[1], uid_buf[2], uid_buf[3]\
				, VERSION, (int)ul_temp, hr, min) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}

/*
*	Create and format HTML for display help page
*
*/
uint8_t interfaceCreate_Display_Home(void)
{
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
				"body {"\
					"overflow: auto;"\
					"font-family:Sans-serif;"\
					"line-height: 1.2em;"\
					"font-size: 17px;"\
					"margin-left: 20px;"\
				"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<h2>Display Help</h2>"\
				"<h3>Ports</h3>"\
					"<p>"\
						"Displays information for each of the Zodiac FX Ethernet ports, including its status, byte/packet statistics, and VLAN configuration."\
					"</p>"\
				"<h3>OpenFlow</h3>"\
					"<p>"\
						"Information about the OpenFlow status and configuration can be found in the OpenFlow display menu. The configured version, and details of the connected controller are also shown."\
					"</p>"\
				"<h3>Flows</h3>"\
					"<p>"\
						"Flow table contents can be viewed in the flows menu."\
					"</p>"\
			"</body>"\
		"</html>"\
	) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}

/*
*	Create and format HTML for display ports page
*
*/
uint8_t interfaceCreate_Display_Ports(uint8_t step)
{
	if(step == 0)
	{
		int currPort;
		
		// Create status strings
		char portStatusch[2][5];
		snprintf(portStatusch[0], 5, "DOWN");
		snprintf(portStatusch[1], 5, "UP");
		
		// Create VLAN type strings
		char portvlType[3][11];
		snprintf(portvlType[0], 11, "Unassigned");
		snprintf(portvlType[1], 11, "OpenFlow");
		snprintf(portvlType[2], 11, "Native");
		
		// Create
		int vlArr[4] = { 0 };
		
		// Count active VLANs, store list value in vlArr
		int x;
		uint8_t vlCtr = 0;
		for (x=0;x<MAX_VLANS;x++)
		{
			if (Zodiac_Config.vlan_list[x].uActive == 1)
			{
				vlArr[vlCtr] = x;
				
				vlCtr++;
			}
		}

		snprintf(shared_buffer, SHARED_BUFFER_LEN,\
			"<!DOCTYPE html>"\
			"<html>"\
				"<head>"\
					"<style>"\
					"body {"\
						"overflow: auto;"\
						"font-family:Sans-serif;"\
						"line-height: 1.2em;"\
						"font-size: 17px;"\
						"margin-left: 20px;"\
					"}"\
					""\
					"table {"\
						"border-collapse: collapse;"\
						"border: 1px solid black;"\
					"}"\
					"td, th {"\
						"height: 27px;"\
						"padding-left: 7px;"\
						"padding-right: 10px;"\
						"border: 1px solid black;"\
					"}"\
					"#row {"\
						"font-weight: bold;"\
					"}"\
					"</style>"\
				"</head>"\
				"<body>"\
					"<p>"\
						"<h2>Port Information</h2>"\
					"</p>"\
					"<form style=\"width: 620px\" action=\"save_ports\" method=\"post\">"\
					"<fieldset>"\
						"<legend>Ports</legend>"\
					"<table>"\
					  "<tr>"\
						"<th></th>"\
						"<th>Port 1</th>"\
						"<th>Port 2</th>"\
						"<th>Port 3</th>"\
						"<th>Port 4</th>"\
					  "</tr>"\
					  "<tr>"\
						"<td id=\"row\">Status:</td>"\
						"<td>%s</td>"\
						"<td>%s</td>"\
						"<td>%s</td>"\
						"<td>%s</td>"\
					"</tr>"\
					"<tr>"\
							"<td id=\"row\">VLAN Type:</td>"\
					, portStatusch[port_status[0]], portStatusch[port_status[1]], portStatusch[port_status[2]], portStatusch[port_status[3]]\
				);
				
		// Create VLAN type for each port
		for(x=0;x<4;x++)
		{
			currPort = x+1;		// Store port
			
			int y = 0;
			uint8_t done = 0;
			if(vlCtr > 0)
			{
				// Active VLANs exist
				
				// Loop to go through each active VLAN and view port mappings
				while(y<vlCtr && !done)
				{
					// Check if the VLAN is assigned to the current port
					if(Zodiac_Config.vlan_list[vlArr[y]].portmap[currPort-1] == 1)
					{
						snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
							"<td>%s</td>"\
								, portvlType[Zodiac_Config.vlan_list[vlArr[y]].uVlanType]\
							);
						done = 1;
					}
					y++;	
				}
				
				if(!done)
				{
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
							"<td>%s</td>"\
					, portvlType[0]\
					);
				}
			}
			else
			{
				// No active VLANs
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
							"<td>%s</td>"\
						, portvlType[0]\
					);
			}
		}
		
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"</tr>"\
						"<tr>"\
							"<td id=\"row\">VLAN ID:</td>"\
			);
		
		// Create VLAN dropdown for each port
		for(x=0;x<4;x++)
		{
			currPort = x+1;		// Store port
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
							"<td>"\
								"<select name=\"wi_p%dID\">"\
								"<option value=\"0\">-</option>"\
						, currPort\
					);
			
			int y;
			if(vlCtr > 0)
			{
				// Loop to write each VLAN option
				for(y=0;y<vlCtr;y++)
				{
					// Check if the VLAN is assigned to the current port
					if(Zodiac_Config.vlan_list[vlArr[y]].portmap[currPort-1] == 1)
					{
						snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
									"<option selected value=\"%d\">%d</option>"\
								, Zodiac_Config.vlan_list[vlArr[y]].uVlanID, Zodiac_Config.vlan_list[vlArr[y]].uVlanID\
							);
					}
					else
					{
						snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
								"<option value=\"%d\">%d</option>"\
							, Zodiac_Config.vlan_list[vlArr[y]].uVlanID, Zodiac_Config.vlan_list[vlArr[y]].uVlanID\
						);
					}
					
				}
			}
				
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
								"</select>"\
							"</td>"\
					);
		}
				
		if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
					"</tr>"\		
				) < SHARED_BUFFER_LEN)
		{
			TRACE("http.c: html (1/2) written to buffer");
			return 1;
		}
		else
		{
			TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
			return 0;
		}
	}
	else if(step == 1)
	{
		if(OF_Version == 1)
		{
			// of v1.0
			if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
							"<tr>"\
							"<td id=\"row\">RX Bytes:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">TX Bytes:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">RX Packets:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">TX Packets:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">RX Dropped Packets:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">TX Dropped Packets:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">RX CRC Errors:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						"</table>"\
						"<br>"\
							"<input type=\"submit\" value=\"Save\">"\
							"<input type=\"reset\" value=\"Cancel\"><br>"\
						"</fieldset>"\
						"</form>"\
					"</body>"\
				"</html>"\
				, phys10_port_stats[0].rx_bytes, phys10_port_stats[1].rx_bytes, phys10_port_stats[2].rx_bytes, phys10_port_stats[3].rx_bytes
				, phys10_port_stats[0].tx_bytes, phys10_port_stats[1].tx_bytes, phys10_port_stats[2].tx_bytes, phys10_port_stats[3].tx_bytes
				, phys10_port_stats[0].rx_packets, phys10_port_stats[1].rx_packets, phys10_port_stats[2].rx_packets, phys10_port_stats[3].rx_packets
				, phys10_port_stats[0].tx_packets, phys10_port_stats[1].tx_packets, phys10_port_stats[2].tx_packets, phys10_port_stats[3].tx_packets
				, phys10_port_stats[0].rx_dropped, phys10_port_stats[1].rx_dropped, phys10_port_stats[2].rx_dropped, phys10_port_stats[3].rx_dropped
				, phys10_port_stats[0].tx_dropped, phys10_port_stats[1].tx_dropped, phys10_port_stats[2].tx_dropped, phys10_port_stats[3].tx_dropped
				, phys10_port_stats[0].rx_crc_err, phys10_port_stats[1].rx_crc_err, phys10_port_stats[2].rx_crc_err, phys10_port_stats[3].rx_crc_err
			) < SHARED_BUFFER_LEN)
			{
				TRACE("http.c: html (2/2) written to buffer");
				return 1;
			}
			else
			{
				TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
				return 0;
			}
		}
		else
		{
			// of v1.3
			if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
							"<tr>"\
							"<td id=\"row\">RX Bytes:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">TX Bytes:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">RX Packets:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">TX Packets:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">RX Dropped Packets:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">TX Dropped Packets:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						  "<tr>"\
							"<td id=\"row\">RX CRC Errors:</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
							"<td>%"PRIu64"</td>"\
						  "</tr>"\
						"</table>"\
						"<br>"\
							"<input type=\"submit\" value=\"Save\">"\
							"<input type=\"reset\" value=\"Cancel\"><br>"\
						"</fieldset>"\
						"</form>"\
					"</body>"\
				"</html>"\
				, phys13_port_stats[0].rx_bytes, phys13_port_stats[1].rx_bytes, phys13_port_stats[2].rx_bytes, phys13_port_stats[3].rx_bytes
				, phys13_port_stats[0].tx_bytes, phys13_port_stats[1].tx_bytes, phys13_port_stats[2].tx_bytes, phys13_port_stats[3].tx_bytes
				, phys13_port_stats[0].rx_packets, phys13_port_stats[1].rx_packets, phys13_port_stats[2].rx_packets, phys13_port_stats[3].rx_packets
				, phys13_port_stats[0].tx_packets, phys13_port_stats[1].tx_packets, phys13_port_stats[2].tx_packets, phys13_port_stats[3].tx_packets
				, phys13_port_stats[0].rx_dropped, phys13_port_stats[1].rx_dropped, phys13_port_stats[2].rx_dropped, phys13_port_stats[3].rx_dropped
				, phys13_port_stats[0].tx_dropped, phys13_port_stats[1].tx_dropped, phys13_port_stats[2].tx_dropped, phys13_port_stats[3].tx_dropped
				, phys13_port_stats[0].rx_crc_err, phys13_port_stats[1].rx_crc_err, phys13_port_stats[2].rx_crc_err, phys13_port_stats[3].rx_crc_err
			) < SHARED_BUFFER_LEN)
			{
				TRACE("http.c: html (2/2) written to buffer");
				return 1;
			}
			else
			{
				TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
				return 0;
			}
		}
	}
	else
	{
		TRACE:("http.c: Display: Ports step error");
	}
}


/*
*	Create and format HTML for display openflow page
*
*/
uint8_t interfaceCreate_Display_OpenFlow(void)
{
	
	// Status
	char wi_ofStatus[15] = "";
	
	if (tcp_pcb->state != ESTABLISHED && Zodiac_Config.OFEnabled == OF_ENABLED)
	{
		snprintf(wi_ofStatus, 15, "Disconnected");
	}
	else if (tcp_pcb->state == ESTABLISHED && Zodiac_Config.OFEnabled == OF_ENABLED)
	{
		snprintf(wi_ofStatus, 15, "Connected");
	}
	else if (Zodiac_Config.OFEnabled == OF_DISABLED)
	{
		snprintf(wi_ofStatus, 15, "Disabled");
	}
	else
	{
		snprintf(wi_ofStatus, 15, "Error: unknown");
	}
	
	// Version, Tables, Flows, Lookups, Matches
	char wi_ofVersion[15] = "";
	int	 wi_ofTables  = 0;
	int  wi_ofFlows   = 0;
	int  wi_ofLookups = 0;
	int  wi_ofMatches = 0;
	
	if (OF_Version == 1)
	{
		snprintf(wi_ofVersion, 15, "1.0");
		wi_ofTables  = 1;
		wi_ofFlows   = iLastFlow;
		wi_ofLookups = table_counters[0].lookup_count;
		wi_ofMatches = table_counters[0].matched_count;
	}
	else if (OF_Version == 4)
	{
		int flow_count;
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
			if(flow_count > 0) wi_ofTables++;
	}
		snprintf(wi_ofVersion, 15, "1.3");
		wi_ofFlows = iLastFlow;
		// Total up all the table stats
		for (int x=0;x<MAX_TABLES;x++)
		{
			wi_ofLookups += table_counters[x].lookup_count;
			wi_ofMatches += table_counters[x].matched_count;
		}
	}
	else
	{
		snprintf(wi_ofVersion, 15, "Auto");
	}
	
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
				"body {"\
					"overflow: auto;"\
					"font-family:Sans-serif;"\
					"line-height: 1.2em;"\
					"font-size: 17px;"\
					"margin-left: 20px;"\
				"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h2>OpenFlow Information</h2>"\
				"</p>"\
				"<form style=\"width: 200px\" action=\"save_none\" method=\"post\" onsubmit=\"return confirm('Zodiac FX needs to restart to apply changes.\n\nPress the restart button on the top right for your changes to take effect.');\">"\
					"<fieldset>"\
						"<legend>OpenFlow</legend>"\
						"Status:<br>"\
						"<input type=\"text\" name=\"wi_ofStatus\" value=\"%s\" readonly><br><br>"\
						"Version:<br>"\
						"<input type=\"text\" name=\"wi_ofVer\" value=\"%s\" readonly><br><br>"\
						"Tables:<br>"\
						"<input type=\"text\" name=\"wi_ofTab\" value=\"%d\" readonly><br><br>"\
						"Flows:<br>"\
						"<input type=\"text\" name=\"wi_ofFlows\" value=\"%d\" readonly><br><br>"\
						"Table Lookups:<br>"\
						"<input type=\"text\" name=\"wi_ofLk\" value=\"%d\" readonly><br><br>"\
						"Table Matches:<br>"\
						"<input type=\"text\" name=\"wi_ofMatch\" value=\"%d\" readonly><br>"\
					"</fieldset>"\
				"</form>"\
			"</body>"\
		"</html>"\
		, wi_ofStatus , wi_ofVersion , wi_ofTables , wi_ofFlows , wi_ofLookups , wi_ofMatches\
	) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}

/*
*	Create and format HTML for display flows page
*
*/
uint8_t interfaceCreate_Display_Flows(void)
{
	snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
				"body {"\
					"overflow: auto;"\
					"font-family:Sans-serif;"\
					"line-height: 1.2em;"\
					"font-size: 17px;"\
					"margin-left: 20px;"\
				"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h2>Flows</h2>"\
				"</p>"\
				"<pre>"\
			);

// Begin Flow formatting

int i;
uint8_t flowLimit;
struct ofp_action_header * act_hdr;

// Limit flows to fit in shared_buffer
if(iLastFlow < 6)
{
	flowLimit = iLastFlow;
}
else
{
	flowLimit = 6;
}

if (iLastFlow > 0)
{
	// OpenFlow v1.0 (0x01) Flow Table
	if( OF_Version == 1)
	{
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n-------------------------------------------------------------------------\r\n");
		for (i=0;i<flowLimit;i++)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\nFlow %d\r\n",i+1);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer)," Match:\r\n");
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Incoming Port: %d\t\t\tEthernet Type: 0x%.4X\r\n",ntohs(flow_match10[i]->match.in_port), ntohs(flow_match10[i]->match.dl_type));
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\t\tDestination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n",flow_match10[i]->match.dl_src[0], flow_match10[i]->match.dl_src[1], flow_match10[i]->match.dl_src[2], flow_match10[i]->match.dl_src[3], flow_match10[i]->match.dl_src[4], flow_match10[i]->match.dl_src[5] \
			, flow_match10[i]->match.dl_dst[0], flow_match10[i]->match.dl_dst[1], flow_match10[i]->match.dl_dst[2], flow_match10[i]->match.dl_dst[3], flow_match10[i]->match.dl_dst[4], flow_match10[i]->match.dl_dst[5]);
			if (ntohs(flow_match10[i]->match.dl_vlan) == 0xffff)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  VLAN ID: N/A\t\t\t\tVLAN Priority: N/A\r\n");
				} else {
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  VLAN ID: %d\t\t\t\tVLAN Priority: 0x%x\r\n",ntohs(flow_match10[i]->match.dl_vlan), flow_match10[i]->match.dl_vlan_pcp);
			}
			if ((ntohs(flow_match10[i]->match.dl_type) == 0x0800) || (ntohs(flow_match10[i]->match.dl_type) == 0x8100)) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  IP Protocol: %d\t\t\tIP ToS Bits: 0x%.2X\r\n",flow_match10[i]->match.nw_proto, flow_match10[i]->match.nw_tos);
			if (flow_match10[i]->match.nw_proto == 7 || flow_match10[i]->match.nw_proto == 16)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  TCP Source Address: %d.%d.%d.%d\r\n",ip4_addr1(&flow_match10[i]->match.nw_src), ip4_addr2(&flow_match10[i]->match.nw_src), ip4_addr3(&flow_match10[i]->match.nw_src), ip4_addr4(&flow_match10[i]->match.nw_src));
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  TCP Destination Address: %d.%d.%d.%d\r\n", ip4_addr1(&flow_match10[i]->match.nw_dst), ip4_addr2(&flow_match10[i]->match.nw_dst), ip4_addr3(&flow_match10[i]->match.nw_dst), ip4_addr4(&flow_match10[i]->match.nw_dst));
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  TCP/UDP Source Port: %d\t\tTCP/UDP Destination Port: %d\r\n",ntohs(flow_match10[i]->match.tp_src), ntohs(flow_match10[i]->match.tp_dst));
			}
			if (flow_match10[i]->match.nw_proto == 1)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  ICMP Type: %d\t\t\t\tICMP Code: %d\r\n",ntohs(flow_match10[i]->match.tp_src), ntohs(flow_match10[i]->match.tp_dst));
			}
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Wildcards: 0x%.8x\t\t\tCookie: 0x%" PRIx64 "\r\n",ntohl(flow_match10[i]->match.wildcards), htonll(flow_match10[i]->cookie));
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r Attributes:\r\n");
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Priority: %d\t\t\tDuration: %d secs\r\n",ntohs(flow_match10[i]->priority), (totaltime/2) - flow_counters[i].duration);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Hard Timeout: %d secs\t\t\tIdle Timeout: %d secs\r\n",ntohs(flow_match10[i]->hard_timeout), ntohs(flow_match10[i]->idle_timeout));
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Byte Count: %d\t\t\tPacket Count: %d\r\n",flow_counters[i].bytes, flow_counters[i].hitCount);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n Actions:\r\n");
			for(int q=0;q<4;q++)
			{
				if(q == 0) act_hdr = flow_actions10[i]->action1;
				if(q == 1) act_hdr = flow_actions10[i]->action2;
				if(q == 2) act_hdr = flow_actions10[i]->action3;
				if(q == 3) act_hdr = flow_actions10[i]->action4;

				if(act_hdr->len == 0 && q == 0) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   DROP\r\n"); // No actions = DROP

				if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_OUTPUT) // Output to port action
				{
					struct ofp_action_output * action_out = act_hdr;
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Action %d:\r\n",q+1);
					if (ntohs(action_out->port) <= 255) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: %d\r\n", ntohs(action_out->port));
					if (ntohs(action_out->port) == OFPP_IN_PORT) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: IN_PORT\r\n");
					if (ntohs(action_out->port) == OFPP_FLOOD) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: FLOOD\r\n");
					if (ntohs(action_out->port) == OFPP_ALL) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: ALL\r\n");
					if (ntohs(action_out->port) == OFPP_CONTROLLER) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: CONTROLLER\r\n");
				}
				if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_SET_VLAN_VID) //
				{
					struct ofp_action_vlan_vid *action_vlanid = act_hdr;
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Action %d:\r\n",q+1);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set VLAN ID: %d\r\n", ntohs(action_vlanid->vlan_vid));
				}

				if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_SET_DL_DST) //
				{
					struct ofp_action_dl_addr *action_setdl = act_hdr;
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Action %d:\r\n",q+1);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", action_setdl->dl_addr[0],action_setdl->dl_addr[1],action_setdl->dl_addr[2],action_setdl->dl_addr[3],action_setdl->dl_addr[4],action_setdl->dl_addr[5]);
				}
				if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_SET_DL_SRC) //
				{
					struct ofp_action_dl_addr *action_setdl = act_hdr;
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Action %d:\r\n",q+1);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", action_setdl->dl_addr[0],action_setdl->dl_addr[1],action_setdl->dl_addr[2],action_setdl->dl_addr[3],action_setdl->dl_addr[4],action_setdl->dl_addr[5]);
				}
				if(act_hdr->len != 0 && ntohs(act_hdr->type) == OFPAT10_STRIP_VLAN) //
				{
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Action %d:\r\n",q+1);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Strip VLAN tag\r\n");
				}
			}
		}
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n-------------------------------------------------------------------------\r\n\n");
	}
	// OpenFlow v1.3 (0x04) Flow Table
	if( OF_Version == 4)
	{
		int match_size;
		int inst_size;
		int act_size;
		struct ofp13_instruction *inst_ptr;
		struct ofp13_instruction_actions *inst_actions;
		struct oxm_header13 oxm_header;
		uint8_t oxm_value8;
		uint16_t oxm_value16;
		uint32_t oxm_value32;
		uint8_t oxm_eth[6];
		uint8_t oxm_ipv4[4];
		uint16_t oxm_ipv6[8];

		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n-------------------------------------------------------------------------\r\n");
		for (i=0;i<flowLimit;i++)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\nFlow %d\r\n",i+1);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer)," Match:\r\n");
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
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  In Port: %d\r\n",ntohl(oxm_value32));
					break;

					case OFPXMT_OFB_ETH_DST:
					memcpy(&oxm_eth, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 6);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
					break;

					case OFPXMT_OFB_ETH_SRC:
					memcpy(&oxm_eth, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 6);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
					break;

					case OFPXMT_OFB_ETH_TYPE:
					memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
					if (ntohs(oxm_value16) == 0x0806)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  ETH Type: ARP\r\n");
					if (ntohs(oxm_value16) == 0x0800)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  ETH Type: IPv4\r\n");
					if (ntohs(oxm_value16) == 0x86dd)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  ETH Type: IPv6\r\n");
					if (ntohs(oxm_value16) == 0x8100)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  ETH Type: VLAN\r\n");
					break;

					case OFPXMT_OFB_IP_PROTO:
					memcpy(&oxm_value8, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 1);
					if (oxm_value8 == 1)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  IP Protocol: ICMP\r\n");
					if (oxm_value8 == 6)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  IP Protocol: TCP\r\n");
					if (oxm_value8 == 17)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  IP Protocol: UDP\r\n");
					break;

					case OFPXMT_OFB_IPV4_SRC:
					if (has_mask)
					{
						memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 8);
						snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Source IP:  %d.%d.%d.%d / %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3], oxm_ipv4[4], oxm_ipv4[5], oxm_ipv4[6], oxm_ipv4[7]);
						} else {
						memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 4);
						snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
					}
					break;

					case OFPXMT_OFB_IPV4_DST:
					if (has_mask)
					{
						memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 8);
						snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Destination IP:  %d.%d.%d.%d / %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3], oxm_ipv4[4], oxm_ipv4[5], oxm_ipv4[6], oxm_ipv4[7]);
						} else {
						memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 4);
						snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Destination IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
					}
					break;

					case OFPXMT_OFB_IPV6_SRC:
					memcpy(&oxm_ipv6, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 16);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Source IP: %.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X\r\n", oxm_ipv6[0], oxm_ipv6[1], oxm_ipv6[2], oxm_ipv6[3], oxm_ipv6[4], oxm_ipv6[5], oxm_ipv6[6], oxm_ipv6[7]);
					break;

					case OFPXMT_OFB_IPV6_DST:
					memcpy(&oxm_ipv6, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 16);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Destination IP:  %.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X\r\n", oxm_ipv6[0], oxm_ipv6[1], oxm_ipv6[2], oxm_ipv6[3], oxm_ipv6[4], oxm_ipv6[5], oxm_ipv6[6], oxm_ipv6[7]);
					break;

					case OFPXMT_OFB_TCP_SRC:
					memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Source TCP Port: %d\r\n",ntohs(oxm_value16));
					break;

					case OFPXMT_OFB_TCP_DST:
					memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Destination TCP Port: %d\r\n",ntohs(oxm_value16));
					break;

					case OFPXMT_OFB_UDP_SRC:
					memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Source UDP Port: %d\r\n",ntohs(oxm_value16));
					break;

					case OFPXMT_OFB_UDP_DST:
					memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Destination UDP Port: %d\r\n",ntohs(oxm_value16));
					break;

					case OFPXMT_OFB_VLAN_VID:
					memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
					if (oxm_value16 != 0) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  VLAN ID: %d\r\n",(ntohs(oxm_value16) - OFPVID_PRESENT));
					break;

				};
				match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
			}
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r Attributes:\r\n");
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Table ID: %d\t\t\t\tCookie:0x%" PRIx64 "\r\n",flow_match13[i]->table_id, htonll(flow_match13[i]->cookie));
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Priority: %d\t\t\t\tDuration: %d secs\r\n",ntohs(flow_match13[i]->priority), (totaltime/2) - flow_counters[i].duration);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Hard Timeout: %d secs\t\t\tIdle Timeout: %d secs\r\n",ntohs(flow_match13[i]->hard_timeout), ntohs(flow_match13[i]->idle_timeout));
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Byte Count: %d\t\t\tPacket Count: %d\r\n",flow_counters[i].bytes, flow_counters[i].hitCount);
			int lm = (totaltime/2) - flow_counters[i].lastmatch;
			int hr = lm/3600;
			int t = lm%3600;
			int min = t/60;
			int sec = t%60;
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Last Match: %02d:%02d:%02d\r\n", hr, min, sec);
			// Print instruction list
			if (ofp13_oxm_inst[i] != NULL)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r Instructions:\r\n");
				inst_ptr = (struct ofp13_instruction *) ofp13_oxm_inst[i];
				inst_size = ntohs(inst_ptr->len);
				if(ntohs(inst_ptr->type) == OFPIT13_APPLY_ACTIONS)
				{
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Apply Actions:\r\n");
					struct ofp13_action_header *act_hdr;
					act_size = 0;
					if (inst_size == sizeof(struct ofp13_instruction_actions)) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   DROP \r\n");	// No actions
					while (act_size < (inst_size - sizeof(struct ofp13_instruction_actions)))
					{
						inst_actions  = ofp13_oxm_inst[i] + act_size;
						act_hdr = &inst_actions->actions;
						if (htons(act_hdr->type) == OFPAT13_OUTPUT)
						{
							struct ofp13_action_output *act_output = act_hdr;
							if (htonl(act_output->port) < OFPP13_MAX)
							{
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output Port: %d\r\n", htonl(act_output->port));
							} else if (htonl(act_output->port) == OFPP13_IN_PORT)
							{
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: IN_PORT \r\n");
							} else if (htonl(act_output->port) == OFPP13_FLOOD)
							{
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: FLOOD \r\n");
							} else if (htonl(act_output->port) == OFPP13_ALL)
							{
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: ALL \r\n");
							} else if (htonl(act_output->port) == OFPP13_CONTROLLER)
							{
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Output: CONTROLLER \r\n");
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
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set VLAN ID: %d\r\n",(ntohs(oxm_value16) - OFPVID_PRESENT));
								break;

								case OFPXMT_OFB_ETH_SRC:
								memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
								break;

								case OFPXMT_OFB_ETH_DST:
								memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
								break;

								case OFPXMT_OFB_ETH_TYPE:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								if (ntohs(oxm_value16) == 0x0806 )snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ETH Type: ARP\r\n");
								if (ntohs(oxm_value16) == 0x0800 )snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ETH Type: IPv4\r\n");
								if (ntohs(oxm_value16) == 0x86dd )snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ETH Type: IPv6\r\n");
								if (ntohs(oxm_value16) == 0x8100 )snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ETH Type: VLAN\r\n");
								break;

								case OFPXMT_OFB_IPV4_SRC:
								memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
								break;

								case OFPXMT_OFB_IP_PROTO:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								if (oxm_value16 == 1)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set IP Protocol: ICMP\r\n");
								if (oxm_value16 == 6)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set IP Protocol: TCP\r\n");
								if (oxm_value16 == 17)snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set IP Protocol: UDP\r\n");
								break;

								case OFPXMT_OFB_IPV4_DST:
								memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set Destination IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
								break;

								case OFPXMT_OFB_TCP_SRC:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set TCP Source Port:  %d\r\n", ntohs(oxm_value16));
								break;

								case OFPXMT_OFB_TCP_DST:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set TCP Destination Port:  %d\r\n", ntohs(oxm_value16));
								break;

								case OFPXMT_OFB_UDP_SRC:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set UDP Source Port:  %d\r\n", ntohs(oxm_value16));
								break;

								case OFPXMT_OFB_UDP_DST:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set UDP Destination Port:  %d\r\n", ntohs(oxm_value16));
								break;

								case OFPXMT_OFB_ICMPV4_TYPE:
								memcpy(&oxm_value8, act_set_field->field + sizeof(struct oxm_header13), 1);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ICMP Type:  %d\r\n", oxm_value8);
								break;

								case OFPXMT_OFB_ICMPV4_CODE:
								memcpy(&oxm_value8, act_set_field->field + sizeof(struct oxm_header13), 1);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ICMP Code:  %d\r\n", oxm_value8);
								break;

								case OFPXMT_OFB_ARP_OP:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ARP OP Code:  %d\r\n", ntohs(oxm_value16));
								break;

								case OFPXMT_OFB_ARP_SPA:
								memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ARP Source IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
								break;

								case OFPXMT_OFB_ARP_TPA:
								memcpy(&oxm_ipv4, act_set_field->field + sizeof(struct oxm_header13), 4);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ARP Target IP:  %d.%d.%d.%d\r\n", oxm_ipv4[0], oxm_ipv4[1], oxm_ipv4[2], oxm_ipv4[3]);
								break;

								case OFPXMT_OFB_ARP_SHA:
								memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ARP Source HA: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
								break;

								case OFPXMT_OFB_ARP_THA:
								memcpy(&oxm_eth, act_set_field->field + sizeof(struct oxm_header13), 6);
								snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Set ARP Target HA: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n", oxm_eth[0], oxm_eth[1], oxm_eth[2], oxm_eth[3], oxm_eth[4], oxm_eth[5]);
								break;

							};
						}

						if (htons(act_hdr->type) == OFPAT13_PUSH_VLAN)
						{
							struct ofp13_action_push *act_push = act_hdr;
							snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Push VLAN tag\r\n");
						}

						if (htons(act_hdr->type) == OFPAT13_POP_VLAN)
						{
							snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   Pop VLAN tag\r\n");
						}

						act_size += htons(act_hdr->len);
					}
				}
				// Print goto table instruction
				if(ntohs(inst_ptr->type) == OFPIT13_GOTO_TABLE)
				{
					struct ofp13_instruction_goto_table *inst_goto_ptr;
					inst_goto_ptr = (struct ofp13_instruction_goto_table *) inst_ptr;
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Goto Table: %d\r\n", inst_goto_ptr->table_id);
					continue;
				}
				// Is there more then one instruction?
				if (ofp13_oxm_inst_size[i] > inst_size)
				{
					uint8_t *nxt_inst;
					nxt_inst = ofp13_oxm_inst[i] + inst_size;
					inst_ptr = (struct ofp13_instruction *) nxt_inst;
					inst_size = ntohs(inst_ptr->len);
					if(ntohs(inst_ptr->type) == OFPIT13_GOTO_TABLE)
					{
						struct ofp13_instruction_goto_table *inst_goto_ptr;
						inst_goto_ptr = (struct ofp13_instruction_goto_table *) inst_ptr;
						snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Goto Table: %d\r\n", inst_goto_ptr->table_id);
					}
				}
				} else {
				// No instructions
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r Instructions:\r\n");
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   DROP \r\n");
			}
		}
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n-------------------------------------------------------------------------\r\n\n");
	}
	} else {
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"No Flows installed!\r\n");
	}
	
// End Flow formatting

	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</pre>"\
				/*"<form action=\"btn_ofNext\" method=\"post\">"\
						"<br><button name=\"btn\" value=\"btn_ofNext\">Next</button>"\
				"</form>"\
				"<form action=\"btn_ofPrev\" method=\"post\">"\
						"<button name=\"btn\" value=\"btn_ofPrev\">Previous</button>"\
				"</form>"\*/
				"<form action=\"btn_ofClear\" method=\"post\"  onsubmit=\"return confirm('All flows will be cleared. Do you wish to proceed?');\">"\
						"<br><button name=\"btn\" value=\"btn_ofClear\">Clear Flows</button>"\
				"</form>"\
			"</body>"\
		"</html>"\
	) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}
			
/*
*	Create and format HTML for config help page
*
*/
uint8_t interfaceCreate_Config_Home(void)
{
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
				"body {"\
					"overflow: auto;"\
					"font-family:Sans-serif;"\
					"line-height: 1.2em;"\
					"font-size: 17px;"\
					"margin-left: 20px;"\
				"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<h2>Config Help</h2>"\
				"<h3>Network</h3>"\
					"<p>"\
						"The network settings of the Zodiac FX can be configured in this menu, including the device name, IP address, MAC address, netmask, and default gateway."\
					"</p>"\
				"<h3>VLANs</h3>"\
					"<p>"\
						"Virtual LANs can be added or removed in the VLANs menu. These can be assigned in the Ports menu on the left."\
					"</p>"\
				"<h3>OpenFlow</h3>"\
					"<p>"\
						"The OpenFlow configuration can be modified here. OpenFlow can be enabled or disabled, the version can be specified, and the failstate can be set. The OpenFlow controller's IP address and port can be configured based on your network."\
					"</p>"\
			"</body>"\
		"</html>"\
		) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}

/*
*	Create and format HTML for config network page
*
*/
uint8_t interfaceCreate_Config_Network(void)
{
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
		"<head>"\
		"<style>"\
		"body {"\
			"overflow: auto;"\
			"font-family:Sans-serif;"\
			"line-height: 1.2em;"\
			"font-size: 17px;"\
			"margin-left: 20px;"\
		"}"\
		"</style>"\
		"</head>"\
		"<body>"\
		"<p>"\
		"<h1>Network Configuration</h1>"\
		"</p>"\
		"<form style=\"width: 200px\" action=\"save_config\" method=\"post\" onsubmit=\"return confirm('Zodiac FX needs to restart to apply changes. Press the restart button on the top right for your changes to take effect.');\">"\
		"<fieldset>"\
		"<legend>Connection</legend>"\
		"Name:<br>"\
		"<input type=\"text\" name=\"wi_deviceName\" value=\"%s\"><br><br>"\
		"MAC Address:<br>"\
		"<input type=\"text\" name=\"wi_macAddress\" value=\"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\"><br><br>"\
		"IP Address:<br>"\
		"<input type=\"text\" name=\"wi_ipAddress\" value=\"%d.%d.%d.%d\"><br><br>"\
		"Netmask:<br>"\
		"<input type=\"text\" name=\"wi_netmask\" value=\"%d.%d.%d.%d\"><br><br>"\
		"Gateway:<br>"\
		"<input type=\"text\" name=\"wi_gateway\" value=\"%d.%d.%d.%d\"><br><br>"\
		"<input type=\"submit\" value=\"Save\">"\
		"<input type=\"reset\" value=\"Cancel\">"\
		"</fieldset>"\
		"</form>"\
		"</body>"\
		"</html>"\
			, Zodiac_Config.device_name\
			, Zodiac_Config.MAC_address[0], Zodiac_Config.MAC_address[1], Zodiac_Config.MAC_address[2], Zodiac_Config.MAC_address[3], Zodiac_Config.MAC_address[4], Zodiac_Config.MAC_address[5]\
			, Zodiac_Config.IP_address[0], Zodiac_Config.IP_address[1], Zodiac_Config.IP_address[2], Zodiac_Config.IP_address[3]\
			, Zodiac_Config.netmask[0], Zodiac_Config.netmask[1], Zodiac_Config.netmask[2], Zodiac_Config.netmask[3]\
			, Zodiac_Config.gateway_address[0], Zodiac_Config.gateway_address[1], Zodiac_Config.gateway_address[2], Zodiac_Config.gateway_address[3]\
		) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}	
}

/*
*	Create and format HTML for config vlans page
*
*/
uint8_t interfaceCreate_Config_VLANs(void)
{
	int x;
	int delRow = 0;
	char wi_vlType[10] = "";
	
	// Opening tags, and base table
	snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
			"<style>"\
			"body {"\
				"overflow: auto;"\
				"font-family:Sans-serif;"\
				"line-height: 1.2em;"\
				"font-size: 17px;"\
				"margin-left: 20px;"\
			"}"\
			"table {"\
				"border-collapse: collapse;"\
				"border: 1px solid black;"\
				"width: 100%;"\
			"}"\
			"td, th {"\
				"height: 25px;"\
				"padding-left: 5px;"\
				"padding-right: 5px;"\
			"}"\
			"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
				"<h2>Virtual LAN Configuration</h2>"\
				"</p>"\
				"<form style=\"width: 405px\" action=\"save_vlan\" method=\"post\">"\
					"<fieldset>"\
					"<legend>VLANs</legend>"\
					"<table border=\"1\">"\
					"<tr>"\
					"<th>ID</th>"\
					"<th>Name</th>"\
					"<th>Type</th>"\
					"<th>Options</th>"\
					"</tr>"\
	);
	
	// Dynamic row

	for (x=0;x<MAX_VLANS;x++)
	{
		if (Zodiac_Config.vlan_list[x].uActive == 1)
		{
			if (Zodiac_Config.vlan_list[x].uVlanType == 0)
			{
				snprintf(wi_vlType, 10, "Undefined");
			}
			else if (Zodiac_Config.vlan_list[x].uVlanType == 1)
			{
				snprintf(wi_vlType, 10, "OpenFlow");
			}
			else if (Zodiac_Config.vlan_list[x].uVlanType == 2)
			{			
				snprintf(wi_vlType, 10, "Native");
			}
	
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
							"<tr>"\
								"<td>%d</td>"\
								"<td>%s</td>"\
								"<td>%s</td>"\
								"<td>"\
									"<button style=\"width:65px\" name=\"btn\" value=\"btn_del%d\">Delete</button>"\
								"</td>"\
							"</tr>"\
							, Zodiac_Config.vlan_list[x].uVlanID, Zodiac_Config.vlan_list[x].cVlanName, wi_vlType, delRow);
			delRow++;
		}
	}
			
	// Final row (input form & ADD button), and closing tags
	if(snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
					"<tr>"\
						"<td>"\
							"<input type=\"text\" name=\"wi_vlID\" size=\"5\">"\
						"</td>"\
						"<td>"\
							"<input type=\"text\" name=\"wi_vlName\" size=\"5\">"\
						"</td>"\
						"<td>"\
							"<select name=\"wi_vlType\">"\
								"<option value=\"1\">OpenFlow</option>"\
								"<option value=\"2\">Native</option>"\
							"</select>"\
						"</td>"\
						"<td>"\
							"<button style=\"width:65px\" name=\"btn\" value=\"btn_add\" size=\"10\">Add</button>"\
						"</td>"\
					"</tr>"\
					"</table>"\
				"</fieldset>"\
			"</form>"\
			"</body>"\
		"</html>"\
		) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: VLAN base written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}

/*
*	Create and format HTML for openflow page
*
*/
uint8_t interfaceCreate_Config_OpenFlow(void)
{	
	snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
				"body {"\
					"overflow: auto;"\
					"font-family:Sans-serif;"\
					"line-height: 1.2em;"\
					"font-size: 17px;"\
					"margin-left: 20px;"\
				"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h2>OpenFlow Configuration</h2>"\
				"</p>"\
				"<form style=\"width: 200px\" action=\"save_of\" method=\"post\" onsubmit=\"return confirm('Zodiac FX needs to restart to apply changes.\n\nPress the restart button on the top right for your changes to take effect.');\">"\
					"<fieldset>"\
						"<legend>OpenFlow</legend>"\
						"Controller IP:<br>"\
						"<input type=\"text\" name=\"wi_ofIP\" value=\"%d.%d.%d.%d\"><br><br>"\
						"Controller Port:<br>"\
						"<input type=\"text\" name=\"wi_ofPort\" value=\"%d\"><br><br>"\
			, Zodiac_Config.OFIP_address[0], Zodiac_Config.OFIP_address[1]
			, Zodiac_Config.OFIP_address[2], Zodiac_Config.OFIP_address[3]
			, Zodiac_Config.OFPort
		);
		
		if(Zodiac_Config.OFEnabled == OF_ENABLED)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"OpenFlow Status:<br>"\
						"<select name=\"wi_ofStatus\">"\
							"<option value=\"Enable\">Enabled</option>"\
							"<option value=\"Disable\">Disabled</option>"\
						"</select><br><br>"\
			);
		}
		else
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"OpenFlow Status:<br>"\
						"<select name=\"wi_ofStatus\">"\
							"<option value=\"Enable\">Enabled</option>"\
							"<option selected value=\"Disable\">Disabled</option>"\
						"</select><br><br>"\
					);
		}
		
		if(Zodiac_Config.failstate == 0)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"Failstate:<br>"\
						"<select name=\"wi_failstate\">"\
							"<option value=\"0\">Secure</option>"\
							"<option value=\"1\">Safe</option>"\
						"</select><br><br>"\
			);
		}
		else
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"Failstate:<br>"\
						"<select name=\"wi_failstate\">"\
							"<option value=\"0\">Secure</option>"\
							"<option selected value=\"1\">Safe</option>"\
						"</select><br><br>"\
					);
		}

		if(Zodiac_Config.of_version == 1)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"OpenFlow Version:<br>"\
						"<select name=\"wi_ofVer\">"\
							"<option value=\"0\">Auto</option>"\
							"<option selected value=\"1\">1.0</option>"\
							"<option value=\"4\">1.3</option>"\
						"</select><br><br>"\
					);
		}
		else if(Zodiac_Config.of_version == 4)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"OpenFlow Version:<br>"\
						"<select name=\"wi_ofVer\">"\
							"<option value=\"0\">Auto</option>"\
							"<option value=\"1\">1.0</option>"\
							"<option selected value=\"4\">1.3</option>"\
						"</select><br><br>"\
					);
		}
		else
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"OpenFlow Version:<br>"\
						"<select name=\"wi_ofVer\">"\
							"<option value=\"0\">Auto</option>"\
							"<option value=\"1\">1.0</option>"\
							"<option value=\"4\">1.3</option>"\
						"</select><br><br>"\
					);
		}
		
		// Final row (input form buttons), and closing tags
		if(snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"<input type=\"submit\" value=\"Save\">"\
						"<input type=\"reset\" value=\"Cancel\">"\
					"</fieldset>"\
				"</form>"\
			"</body>"\
		"</html>"\
		) < SHARED_BUFFER_LEN)
		{
			TRACE("http.c: OpenFlow Config page written to buffer");
			return 1;
		}
		else
		{
			TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
			return 0;
		}
}

/*
*	Create and format HTML for about page
*
*/
uint8_t interfaceCreate_About(void)
{
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
				"body {"\
					"overflow: auto;"\
					"font-family:Sans-serif;"\
					"line-height: 1.2em;"\
					"font-size: 17px;"\
					"margin-left: 20px;"\
				"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<h2>About</h2>"\
				"<h3>Zodiac FX</h3>"\
					"<p>"\
						"The Zodiac FX was created to allow the development of SDN applications on real hardware."\
					"</p>"\
			"</body>"\
		"</html>"\
				) < SHARED_BUFFER_LEN)
	{
		TRACE("http.c: html written to buffer");
		return 1;
	}
	else
	{
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}
