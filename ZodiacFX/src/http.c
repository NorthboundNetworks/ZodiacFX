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
extern struct table_counter table_counters[MAX_TABLES];
extern int iLastFlow;
extern struct tcp_pcb *tcp_pcb;
extern int OF_Version;
extern struct ofp13_flow_mod *flow_match13[MAX_FLOWS_13];

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
				i = 0;
				for(i;i<4;i++)
				{
					if(interfaceCreate_Display_Ports(i))
					{
						if(i < 3)
						{
							// Only write to buffer - don't send
							http_send(&shared_buffer, pcb, 0);
						}
						else
						{
							// Call TCP output & close the connection
							http_send(&shared_buffer, pcb, 1);
							TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
						}
					}
					else
					{
						TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
					}
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
	// Check port status
	char portStatusch[5];
	
	if(port_status[step] == 1)
	{
		snprintf(portStatusch, 5, "UP");			
	}
	else
	{
		snprintf(portStatusch, 5, "DOWN");
	}
	
	if(step == 0)
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
					"#p1 {"\
						"position: fixed;"\
						"top: 60px;"\
						"left: 20px;"\
					"}"\
					"#p2 {"\
						"position: fixed;"\
						"top: 60px;"\
						"left: 230px;"\
					"}"\
					"#p3 {"\
						"position: fixed;"\
						"top: 60px;"\
						"left: 440px;"\
					"}"\
					"#p4 {"\
						"position: fixed;"\
						"top: 60px;"\
						"left: 650px;"\
					"}"\
					"</style>"\
				"</head>"\
				"<body>"\
					"<p>"\
						"<h2>Port Information</h2>"\
					"</p>"\
					"<div id=p1>"\
					  "<br>"\
					  "<form action=\"save_port1\" method=\"post\">"\
							"<fieldset>"\
								"<legend>Port 1</legend>"\
								"Status:<br>"\
								"<input type=\"text\" name=\"wi_portStatus\" value=\"UP\" readonly><br><br>"\
								"VLAN Type:<br>"\
								"<input type=\"text\" name=\"wi_vlanType\" value=\"OpenFlow\" readonly><br><br>"\
								"VLAN ID:<br>"\
								"<select name=\"wi_vlanID\">"\
									"<option          value=\"0\">100</option>"\
									"<option          value=\"1\">200</option>"\
								"</select>"\
								"<input type=\"submit\" value=\"Save\">"\
								"<input type=\"reset\" value=\"Cancel\"><br><br>"\
								"RX Bytes<br>"\
								"<input type=\"text\" name=\"wi_rxB\" value=\"97701\" readonly><br><br>"\
								"TX Bytes<br>"\
								"<input type=\"text\" name=\"wi_txB\" value=\"69865\" readonly><br><br>"\
								"RX Packets<br>"\
								"<input type=\"text\" name=\"wi_rxP\" value=\"1016\" readonly><br><br>"\
								"TX Packets<br>"\
								"<input type=\"text\" name=\"wi_txP\" value=\"724\" readonly><br><br>"\
								"RX Dropped Packets<br>"\
								"<input type=\"text\" name=\"wi_rxDP\" value=\"0\" readonly><br><br>"\
								"TX Dropped Packets<br>"\
								"<input type=\"text\" name=\"wi_txDP\" value=\"0\" readonly><br><br>"\
								"RX CRC Errors<br>"\
								"<input type=\"text\" name=\"wi_rxCRC\" value=\"0\" readonly><br>"\
							"</fieldset>"\
						"</form>"\
					"</div>"\
				//, portStatusch
				//, Zodiac_Config.vlan_list[step].cVlanName
				//, Zodiac_Config.vlan_list[step].uVlanID
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
	else if(step == 1)
	{
		if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
			"<div id=p2>"\
			"<br>"\
			  "<form action=\"save_port2\" method=\"post\">"\
					"<fieldset>"\
						"<legend>Port 2</legend>"\
						"Status:<br>"\
						"<input type=\"text\" name=\"wi_portStatus\" value=\"DOWN\" readonly><br><br>"\
						"VLAN Type:<br>"\
						"<input type=\"text\" name=\"wi_vlanType\" value=\"OpenFlow\" readonly><br><br>"\
						"VLAN ID:<br>"\
						"<select name=\"wi_vlanID\">"\
							"<option          value=\"0\">100</option>"\
							"<option          value=\"1\">200</option>"\
						"</select>"\
						"<input type=\"submit\" value=\"Save\">"\
						"<input type=\"reset\" value=\"Cancel\"><br><br>"\
						"RX Bytes<br>"\
						"<input type=\"text\" name=\"wi_rxB\" value=\"97701\" readonly><br><br>"\
						"TX Bytes<br>"\
						"<input type=\"text\" name=\"wi_txB\" value=\"69865\" readonly><br><br>"\
						"RX Packets<br>"\
						"<input type=\"text\" name=\"wi_rxP\" value=\"1016\" readonly><br><br>"\
						"TX Packets<br>"\
						"<input type=\"text\" name=\"wi_txP\" value=\"724\" readonly><br><br>"\
						"RX Dropped Packets<br>"\
						"<input type=\"text\" name=\"wi_rxDP\" value=\"0\" readonly><br><br>"\
						"TX Dropped Packets<br>"\
						"<input type=\"text\" name=\"wi_txDP\" value=\"0\" readonly><br><br>"\
						"RX CRC Errors<br>"\
						"<input type=\"text\" name=\"wi_rxCRC\" value=\"0\" readonly><br>"\
					"</fieldset>"\
				"</form>"\
			"</div>"\
				//, portStatusch
				//, Zodiac_Config.vlan_list[step].cVlanName
				//, Zodiac_Config.vlan_list[step].uVlanID
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
	else if(step == 2)
	{
		if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
			"<div id=p3>"\
			"<br>"\
			  "<form action=\"save_port3\" method=\"post\">"\
					"<fieldset>"\
						"<legend>Port 3</legend>"\
						"Status:<br>"\
						"<input type=\"text\" name=\"wi_portStatus\" value=\"DOWN\" readonly><br><br>"\
						"VLAN Type:<br>"\
						"<input type=\"text\" name=\"wi_vlanType\" value=\"Native\" readonly><br><br>"\
						"VLAN ID:<br>"\
						"<select name=\"wi_vlanID\">"\
							"<option          value=\"0\">100</option>"\
							"<option          value=\"1\">200</option>"\
						"</select>"\
						"<input type=\"submit\" value=\"Save\">"\
						"<input type=\"reset\" value=\"Cancel\"><br><br>"\
						"RX Bytes<br>"\
						"<input type=\"text\" name=\"wi_rxB\" value=\"97701\" readonly><br><br>"\
						"TX Bytes<br>"\
						"<input type=\"text\" name=\"wi_txB\" value=\"69865\" readonly><br><br>"\
						"RX Packets<br>"\
						"<input type=\"text\" name=\"wi_rxP\" value=\"1016\" readonly><br><br>"\
						"TX Packets<br>"\
						"<input type=\"text\" name=\"wi_txP\" value=\"724\" readonly><br><br>"\
						"RX Dropped Packets<br>"\
						"<input type=\"text\" name=\"wi_rxDP\" value=\"0\" readonly><br><br>"\
						"TX Dropped Packets<br>"\
						"<input type=\"text\" name=\"wi_txDP\" value=\"0\" readonly><br><br>"\
						"RX CRC Errors<br>"\
						"<input type=\"text\" name=\"wi_rxCRC\" value=\"0\" readonly><br>"\
					"</fieldset>"\
				"</form>"\
			"</div>"\
				//, portStatusch
				//, Zodiac_Config.vlan_list[step].cVlanName
				//, Zodiac_Config.vlan_list[step].uVlanID
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
	else if(step == 3)
	{
		if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
					"<div id=p4>"\
						"<br>"\
						  "<form action=\"save_port1\" method=\"post\">"\
								"<fieldset>"\
									"<legend>Port 4</legend>"\
									"Status:<br>"\
									"<input type=\"text\" name=\"wi_portStatus\" value=\"UP\" readonly><br><br>"\
									"VLAN Type:<br>"\
									"<input type=\"text\" name=\"wi_vlanType\" value=\"Native\" readonly><br><br>"\
									"VLAN ID:<br>"\
									"<select name=\"wi_vlanID\">"\
										"<option          value=\"0\">100</option>"\
										"<option          value=\"1\">200</option>"\
									"</select>"\
									"<input type=\"submit\" value=\"Save\">"\
									"<input type=\"reset\" value=\"Cancel\"><br><br>"\
									"RX Bytes<br>"\
									"<input type=\"text\" name=\"wi_rxB\" value=\"97701\" readonly><br><br>"\
									"TX Bytes<br>"\
									"<input type=\"text\" name=\"wi_txB\" value=\"69865\" readonly><br><br>"\
									"RX Packets<br>"\
									"<input type=\"text\" name=\"wi_rxP\" value=\"1016\" readonly><br><br>"\
									"TX Packets<br>"\
									"<input type=\"text\" name=\"wi_txP\" value=\"724\" readonly><br><br>"\
									"RX Dropped Packets<br>"\
									"<input type=\"text\" name=\"wi_rxDP\" value=\"0\" readonly><br><br>"\
									"TX Dropped Packets<br>"\
									"<input type=\"text\" name=\"wi_txDP\" value=\"0\" readonly><br><br>"\
									"RX CRC Errors<br>"\
									"<input type=\"text\" name=\"wi_rxCRC\" value=\"0\" readonly><br>"\
								"</fieldset>"\
							"</form>"\
						"</div>"\
					"</body>"\
				"</html>"\
			//, portStatusch
			//, Zodiac_Config.vlan_list[step].cVlanName
			//, Zodiac_Config.vlan_list[step].uVlanID
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
					"<h2>Flows</h2>"\
				"</p>"\
				"<pre>"\
		"Flow 1\n"\
		"Match:\n"\
		"Attributes :\n"\
		"Priority :  Duration :  secs\n"\
		"Hard Timeout :  secs Idle Timeout :  secs\n"\
		"Byte Count :  Packet Count : \n"\
		"Instructions :\n"\
		"Apply Actions :\n"\
		"Output : CONTROLLER\n"\
		"Flow 2\n"\
		"...\n"\
		"Flow 3\n"\
		"...\n"\
				"</pre>"\
				"<form action=\"btn_ofNext\" method=\"post\">"\
						"<br><button name=\"btn\" value=\"btn_ofNext\">Next</button>"\
				"</form>"\
				"<form action=\"btn_ofPrev\" method=\"post\">"\
						"<button name=\"btn\" value=\"btn_ofPrev\">Previous</button>"\
				"</form>"\
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