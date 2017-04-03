/**
 * @file
 * http.c
 *
 * This file contains the http functions
 *
 */

/*
 * This file is part of the Zodiac FX firmware.
 * Copyright (c) 2016 Google Inc.
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
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];	// SHARED_BUFFER_LEN must never be reduced below 2048
extern int tcp_con_state;	// Check connection state

extern struct ofp_flow_mod *flow_match10[MAX_FLOWS_10];
extern struct ofp13_flow_mod *flow_match13[MAX_FLOWS_13];
extern uint8_t *ofp13_oxm_match[MAX_FLOWS_13];
extern uint8_t *ofp13_oxm_inst[MAX_FLOWS_13];
extern uint16_t ofp13_oxm_inst_size[MAX_FLOWS_13];
extern struct flows_counter flow_counters[MAX_FLOWS_13];
extern struct flow_tbl_actions *flow_actions10[MAX_FLOWS_13];
extern struct meter_entry13 *meter_entry[MAX_METER_13];
extern struct meter_band_stats_array band_stats_array[MAX_METER_13];
extern int iLastFlow;
extern int iLastMeter;
extern struct ofp10_port_stats phys10_port_stats[4];
extern struct ofp13_port_stats phys13_port_stats[4];
extern struct table_counter table_counters[MAX_TABLES];

// Local Variables
struct tcp_pcb *http_pcb;
static char http_msg[64];			// Buffer for HTTP message filtering
static char post_msg[64];			// Buffer for HTTP message filtering
static int page_ctr = 1;
static int boundary_start = 1;		// Check for start of data
static uint8_t flowBase = 0;		// Current set of flows to display
static uint8_t meterBase = 0;		// Current set of meters to display
static struct tcp_pcb * upload_pcb;	// Firmware upload connection check (pcb pointer)
static int upload_port = 0;
static int upload_timer = 0;		// Timer for firmware upload timeout
static struct http_conns http_conn[MAX_CONN];	// http connection status

// Flag variables
bool restart_required_outer = false;
static bool restart_required = false;		// Track if any configuration changes are pending a restart
static bool file_upload = false;	// Multi-part firmware file upload flag
static bool post_pending = false;

static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t http_accept(void *arg, struct tcp_pcb *pcb, err_t err);
void http_send(char *buffer, struct tcp_pcb *pcb, bool out);
static err_t http_sent(void *arg, struct tcp_pcb *tpcb, uint16_t len);
void http_close(struct tcp_pcb *pcb);

static uint8_t upload_handler(char *payload, int len);

// HTML resources
static uint8_t interfaceCreate_Frames(void);
static uint8_t interfaceCreate_Header(void);
static uint8_t interfaceCreate_Menu(void);
static uint8_t interfaceCreate_Home(void);
static uint8_t interfaceCreate_Upload(void);
static uint8_t interfaceCreate_Upload_Status(uint8_t sel);
static uint8_t interfaceCreate_Display_Home(void);
static uint8_t interfaceCreate_Display_Ports(uint8_t step);
static uint8_t interfaceCreate_Display_OpenFlow(void);
static uint8_t interfaceCreate_Display_Flows(void);
static uint8_t interfaceCreate_Display_Meters(void);
static uint8_t interfaceCreate_Config_Home(void);
static uint8_t interfaceCreate_Config_Network(void);
static uint8_t interfaceCreate_Config_VLANs(void);
static uint8_t interfaceCreate_Config_OpenFlow(void);
static uint8_t interfaceCreate_About(void);
static uint8_t interfaceCreate_Restart(void);

static uint8_t http_header[] =		"HTTP/1.1 200 OK\r\n"\
									"Connection: Keep-Alive\r\n"\
									"Content-Type: text/html; charset=UTF-8\r\n\r\n";

static uint8_t html_style_body[] =	"body {"\
										"overflow: auto;"\
										"font-family:Sans-serif;"\
										"line-height: 1.2em;"\
										"font-size: 17px;"\
										"margin-left: 20px;"\
									"}";

// Configuration functions
static uint8_t Config_Network(char *payload, int len);


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
	tcp_sent(pcb, http_sent);
	return ERR_OK;
}

/*
*	HTTP Sent callback function
*
*	@param *arg - pointer the additional TCP args
*	@param *tcp_pcb - pointer the TCP session structure.
*
*/
static err_t http_sent(void *arg, struct tcp_pcb *tpcb, uint16_t len)
{
	TRACE("http.c: [http_sent] %d bytes sent", len);
	for(int i=0; i<MAX_CONN; i++)
	{
		if(http_conn[i].attached_pcb == tpcb)
		{
			TRACE("http.c: pcb 0x%08x waiting on (%d down to %d) bytes", http_conn[i].attached_pcb, http_conn[i].bytes_waiting, http_conn[i].bytes_waiting - len);
			http_conn[i].bytes_waiting -= len;
			if(http_conn[i].bytes_waiting < 0)
			{
				TRACE("http.c: ERROR - illegal bytes_waiting value. Connection will be closed.");
				http_close(http_conn[i].attached_pcb);
			}
			http_conn[i].timeout = sys_get_ms();	// Update timeout timer
			if (http_conn[i].bytes_waiting == 0 && http_conn[i].attached_pcb != NULL) http_close(http_conn[i].attached_pcb);
			break;
		}
		
		if(http_conn[i].attached_pcb != NULL)
		{
			if(sys_get_ms() - http_conn[i].timeout > 3000)	// 3s connection timeout
			{
				TRACE("http.c: pcb 0x%08x has timed out. Connection will be closed.", http_conn[i].attached_pcb);
				http_close(http_conn[i].attached_pcb);
			}	
		}
	}
	if(restart_required == true)
	{
		// Indicates to task_command() that a restart is required on the next loop
		// This allows the 'Restarting...' page to display before the restart occurs
		restart_required_outer = true;
	}
	
	return ERR_OK;
}
	
/*
*	HTTP receive function
*
*/
static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{	
	// Local variables
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
		
		TRACE("http.c: -- HTTP recv received %d/%d payload bytes in this pbuf", p->len, p->tot_len);
		TRACE("http.c: -> pcb @ addr: 0x%08x, remote port %d", pcb, pcb->remote_port);
		
		if(file_upload == true)
		{			
			TRACE("http.c: %d ms since last firmware packet received", (sys_get_ms() - upload_timer));
			
			// Check upload timeout
			if(upload_timer != 0 && sys_get_ms() - upload_timer > UPLOAD_TIMEOUT)
			{
				TRACE("http.c: firmware upload has timed out");
				
				/* Header request check */
				memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
				
				// Specified resource directly follows GET
				i = 0;
				while(i < 63 && (http_payload[i+5] != ' '))
				{
					http_msg[i] = http_payload[i+5];	// Offset http_payload to isolate resource
					i++;
				}
				
				// The "upload failed" message does not need to show up in the header
				if(strcmp(http_msg,"header.htm") != 0)
				{
					// Stop upload operation
					upload_handler(NULL, 0);	// Clean up upload operation
					if(interfaceCreate_Upload_Status(2))
					{
						http_send(&shared_buffer, pcb, 1);
						TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
					}
					else
					{
						TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
					}
				}
			}
			
			if(upload_pcb != pcb && upload_port != pcb->remote_port)
			{
				TRACE("http.c: incoming connection ignored - upload currently in progress");
				
				/* Header request check */
				memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
				
				// Specified resource directly follows GET
				i = 0;
				while(i < 63 && (http_payload[i+5] != ' '))
				{
					http_msg[i] = http_payload[i+5];	// Offset http_payload to isolate resource
					i++;
				}
				
				// The "upload in progress" message does not need to show up in the header
				if(strcmp(http_msg,"header.htm") != 0)
				{
					if(interfaceCreate_Upload_Status(4))
					{
						http_send(&shared_buffer, pcb, 1);
						TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
					}
					else
					{
						TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
					}
				}
				
				return ERR_OK;
			}
			
			// Update timer value (new firmware packet received)
			upload_timer = sys_get_ms();
			
			int ret = 0;
			// Handle multi-part file data
			ret = upload_handler(http_payload, len);
			if(ret == 2)
			{
				file_upload = false;
				boundary_start = 1;
				//flash_clear_gpnvm(1);
				// upload check
				if(verification_check() == SUCCESS)
				{
					upload_handler(NULL, 0);	// Clean up upload operation
					if(interfaceCreate_Upload_Status(1))
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
					upload_handler(NULL, 0);	// Clean up upload operation
					if(interfaceCreate_Upload_Status(3))
					{
						http_send(&shared_buffer, pcb, 1);
						TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
					}
					else
					{
						TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
					}
				}
			}
		}
		else
		{
			// Check HTTP method
			i = 0;
			while(i < 63 && (http_payload[i] != ' '))
			{
				http_msg[i] = http_payload[i];
				i++;
			}
	
			if(strcmp(http_msg,"GET") == 0)
			{			
				TRACE("http.c: GET method received");
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
				if(http_msg[0] == '\0' || strcmp(http_msg,"frames.html") == 0)
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
				else if(strcmp(http_msg,"upload.htm") == 0)
				{
					if(interfaceCreate_Upload())
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
				else if(strcmp(http_msg,"d_meters.htm") == 0)
				{
					if(interfaceCreate_Display_Meters())
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
			
			else if(strcmp(http_msg,"POST") == 0 && post_pending == false)
			{
				TRACE("http.c: POST method received");
				memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array

				// Specified resource directly follows POST
				i = 0;
				while(i < 63 && (http_payload[i+6] != ' '))
				{
					http_msg[i] = http_payload[i+6];	// Offset http_payload to isolate resource
					i++;
				}
				memcpy(post_msg, http_msg, 64);
				TRACE("http.c: request for %s", post_msg);
				post_pending = true;
				pbuf_free(p);
				return ERR_OK;
			}
			else
			{
				TRACE("http.c: unknown HTTP method received");
			}

					
			if(post_pending == true)
			{
				post_pending = false;
				if(strcmp(post_msg,"upload") == 0)
				{
					// Initialize flash programming
					if(firmware_update_init())
					{
						TRACE("http.c: firmware update initialisation successful");
					}
					else
					{
						TRACE("http.c: firmware update initialisation failed");
					}
					
					// All following packets will contain multi-part file data
					file_upload = true;
					// Store pcb pointer value for this connection
					upload_pcb = pcb;
					// Store remote port
					upload_port = pcb->remote_port;
					// Initialize timeout value
					upload_timer = sys_get_ms();
					
					upload_handler(http_payload, len);
				}
				else if(strcmp(post_msg,"save_config") == 0)
				{
					if(Config_Network(http_payload, len) == SUCCESS)
					{
						TRACE("http.c: network configuration successful");
							
						// Send updated config page
						if(interfaceCreate_Config_Network())
						{
							http_send(&shared_buffer, pcb, 1);
							TRACE("http.c: updated page sent successfully - %d bytes", strlen(shared_buffer));
							return SUCCESS;
						}
						else
						{
							TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
							return FAILURE;
						}
					}
					else
					{
						TRACE("http.c: ERROR: network configuration failed");
					}
				}
				else if(strcmp(post_msg,"btn_restart") == 0)
				{
					if(interfaceCreate_Restart())
					{
						http_send(&shared_buffer, pcb, 1);
						TRACE("http.c: updated page sent successfully - %d bytes", strlen(shared_buffer));
					}
					else
					{
						TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
					}
					restart_required = true;
				}
				else if(strcmp(post_msg,"btn_default") == 0)
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
					software_reset();
				}
				else if(strcmp(post_msg,"save_ports") == 0)
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
							while(	i < 4									// Limit no. digits
									&& (pdat[i] >= 48 && pdat[i] <= 57)		// Only digits allowed
									&& &pdat[i] < http_payload+len				// Prevent overrun of payload data
								)
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
				else if(strcmp(post_msg,"btn_ofPage") == 0)
				{
					// Display: Flows, Previous and Next flow page buttons
					
					if(strstr(http_payload, "btn_ofNext") != NULL)	// Check that element exists
					{
						TRACE("http.c: request for next page of flows");
						TRACE("http.c: current flowBase: %d; current iLastFlow: %d;", flowBase, iLastFlow)
						if(flowBase < iLastFlow-FLOW_DISPLAY_LIMIT)
						{
							// Increment flow base (display next set on page send)
							flowBase += FLOW_DISPLAY_LIMIT;
							TRACE("http.c: new flowBase: %d; current iLastFlow: %d;", flowBase, iLastFlow)
						}
						else
						{
							TRACE("http.c: flowBase already reaches end - NOT incremented")
						}
					}
					else if(strstr(http_payload, "btn_ofPrev") != NULL)
					{
						TRACE("http.c: request for previous page of flows");
						TRACE("http.c: current flowBase: %d; current iLastFlow: %d;", flowBase, iLastFlow)
						if(flowBase >= FLOW_DISPLAY_LIMIT)
						{
							// Decrement flow base (display previous set on page send)
							flowBase -= FLOW_DISPLAY_LIMIT;
							TRACE("http.c: new flowBase: %d; current iLastFlow: %d;", flowBase, iLastFlow)
						}
						else
						{
							TRACE("http.c: flowBase already at start - NOT decremented")
						}
					}
					else
					{
						TRACE("http.c: ERROR: invalid request");
					}
					
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
				else if(strcmp(post_msg,"btn_ofClear") == 0)
				{
					// Display: Flows
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
				else if(strcmp(post_msg,"btn_meterPage") == 0)
				{
					// Display: Meters, Previous and Next meter page buttons
					
					if(strstr(http_payload, "btn_meterNext") != NULL)	// Check that element exists
					{
						TRACE("http.c: request for next page of meters");
						TRACE("http.c: current meterBase: %d; current iLastMeter: %d;", meterBase, iLastMeter)
						if(meterBase < iLastMeter-METER_DISPLAY_LIMIT)
						{
							// Increment flow base (display next set on page send)
							meterBase += METER_DISPLAY_LIMIT;
							TRACE("http.c: new meterBase: %d; current iLastMeter: %d;", meterBase, iLastMeter)
						}
						else
						{
							TRACE("http.c: meterBase already reaches end - NOT incremented")
						}
					}
					else if(strstr(http_payload, "btn_meterPrev") != NULL)
					{
						TRACE("http.c: request for previous page of meters");
						TRACE("http.c: current meterBase: %d; current iLastMeter: %d;", meterBase, iLastMeter)
						if(meterBase >= METER_DISPLAY_LIMIT)
						{
							// Decrement meter base (display previous set on page send)
							meterBase -= METER_DISPLAY_LIMIT;
							TRACE("http.c: new meterBase: %d; current iLastMeter: %d;", meterBase, iLastMeter)
						}
						else
						{
							TRACE("http.c: meterBase already at start - NOT decremented")
						}
					}
					else
					{
						TRACE("http.c: ERROR: invalid request");
					}
					
					// Send updated page
					if(interfaceCreate_Display_Meters())
					{
						http_send(&shared_buffer, pcb, 1);
						TRACE("http.c: updated page sent successfully - %d bytes", strlen(shared_buffer));
					}
					else
					{
						TRACE("http.c: unable to serve updated page - buffer at %d bytes", strlen(shared_buffer));
					}
				}
				else if(strcmp(post_msg,"save_vlan") == 0)
				{
					// Config: VLANs, Add and Delete buttons
					
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
					
						if(vlID <= 4096)
						{
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
							TRACE("http.c: VLAN ID > 4096")
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
				else if(strcmp(post_msg,"save_of") == 0)
				{
					// Config: OpenFlow, Save OpenFlow configuration
					
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
							if (strlen(http_msg) <= 15 )
							{
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
								TRACE("http.c: incorrect IP format");
							}
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

		}
	}
	else
	{
		if(err != ERR_OK)
		{
			TRACE("http.c: receive error - %d", err);
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
*	Parameters:
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
		TRACE("http.c: tcp buffer %d/%d", len, buf_size);

		// Check if data is a part of a larger write
		for(int i=0; i<MAX_CONN; i++)
		{
			if(http_conn[i].attached_pcb == pcb)
			{
				http_conn[i].bytes_waiting += len;
				TRACE("http.c: %d bytes appended to byte counter for pcb @ addr: 0x%08x", len, pcb);
				return;
			}
		}
		
		// If not, attach to a new connection
		for(int i=0; i<MAX_CONN; i++)
		{
			if(http_conn[i].attached_pcb == NULL)
			{
				http_conn[i].attached_pcb = pcb;
				http_conn[i].bytes_waiting += len;
				TRACE("http.c: %d bytes attached to pcb @ addr: 0x%08x", len, pcb);
				return;
			}
		}
	}
	
	return;
}

/*
*	HTTP Close function
*
*	Parameters:
*		pcb - pcb of the connection to close
*/
void http_close(struct tcp_pcb *pcb)
{
	tcp_output(pcb);
	TRACE("http.c: calling tcp_output & closing connection (pcb @ addr: 0x%08x)", pcb);
	tcp_close(pcb);
	// Clear http_conn entry
	for(int i=0; i<MAX_CONN; i++)
	{
		if(http_conn[i].attached_pcb == pcb)
		{
			TRACE("http.c: clearing http_conn for pcb @ addr: 0x%08x", pcb)
			http_conn[i].attached_pcb = NULL;
			http_conn[i].bytes_waiting = 0;
		}
	}
	return;
}
/*
*	Upload handler function
*
*	Details:
*		Handles part-by-part firmware upload process
*
*	Parameters:
*		payload	- pointer to payload data
*		len		- length of payload
*/
static uint8_t upload_handler(char *payload, int len)
{
	static char page[IFLASH_PAGE_SIZE] = {0};			// Storage for each page of data
	static uint16_t saved_bytes = 0;					// Persistent counter of unwritten data
	uint16_t handled_bytes = 0;							// Counter of handled data
	static uint32_t total_handled_bytes = 0;			// Counter of total handled data
	static char boundary_ID[BOUNDARY_MAX_LEN] = {0};	// Storage for boundary ID

	if(payload == NULL || len == 0)
	{
		// Clean up upload handler (on interrupted/failed upload)
		memset(&page, 0, IFLASH_PAGE_SIZE);				// Clear page storage
		memset(&boundary_ID, 0, BOUNDARY_MAX_LEN);		// Clear boundary storage
		saved_bytes = 0;								// Clear saved byte counter
		file_upload = false;							// Clear file upload flag
		boundary_start = 1;								// Set starting boundary required flag
		upload_pcb = NULL;								// Clear pcb connection pointer
		upload_timer = 0;								// Clear upload timeout
		total_handled_bytes = 0;
		return 1;
	}
	
	char *px;			// Start address pointer
	char *py;			// End address pointer
	int i = 0;
	int final = 0;		// Final page flag (set after ending boundary is found)
	int data_len = 0;	// Length of actual upload data
	
	TRACE("http.c: -- upload handler received %d payload bytes", len)
	
	if(boundary_start)
	{
		// Store the boundary ID
		
		memset(&shared_buffer, 0, SHARED_BUFFER_LEN);	// Clear shared_buffer
		
		i = 0;
		while(i < len)
		{
			shared_buffer[i] = payload[i];
			i++;
		}
			
		px = strstr(shared_buffer, "----");
		if(px == NULL)
		{
			TRACE("http.c: boundary ID not found - waiting for next packet");
			return 0;
		}
		else
		{
			memset(&boundary_ID, 0, BOUNDARY_MAX_LEN);
			// Traverse forward until the ID begins
			while(*px == '\x2d')
			{
				px++;
			}
			// Store entirety of boundary ID
			i = 0;
			while(i < BOUNDARY_MAX_LEN && *px != '\x2d' && *px != '\x0d' && *px != '\x0a')
			{
				boundary_ID[i] = *px;
			
				px++;
				i++;
			}
			TRACE("http.c: boundary ID : %s", boundary_ID);
		}
		
		memset(&shared_buffer, 0, SHARED_BUFFER_LEN);	// Clear shared_buffer
		
		// Search for starting boundary (support MIME types)
		if(strstr(payload, "application/mac-binary") != NULL)
		{
			px = strstr(payload, "application/mac-binary");
			px += (strlen("application/mac-binary"));
		}
		else if(strstr(payload, "application/macbinary") != NULL)
		{
			px = strstr(payload, "application/macbinary");
			px += (strlen("application/macbinary"));
		}
		else if(strstr(payload, "application/octet-stream") != NULL)
		{
			px = strstr(payload, "application/octet-stream");
			px += (strlen("application/octet-stream"));
		}
		else if(strstr(payload, "application/x-binary") != NULL)
		{
			px = strstr(payload, "application/x-binary");
			px += (strlen("application/x-binary"));
		}
		else if(strstr(payload, "application/x-macbinary") != NULL)
		{
			px = strstr(payload, "application/x-macbinary");
			px += (strlen("application/x-macbinary"));
		}
		else
		{
			px = NULL;
		}

		if(px == NULL)
		{
			TRACE("http.c: starting boundary not found - waiting for next packet");
			return 0;
		}
		else
		{
			TRACE("http.c: starting boundary found");
		
			// Search for start of data
			i = 0;
			while(((*px) == '\x0a' || (*(px)) == '\x0d') && (i<20))
			{
				px++;
				i++;
				// 'i' will be incremented to 21 if this line is run
			}
					
			if(i == 20)
			{
				TRACE("http.c: start of data part not found");
				return 0;
			}
		
			TRACE("http.c: pointer moved to start of data");
			
			// Starting boundary has been handled
			boundary_start = 0;
			
			// Clear page array before use
			memset(&page, 0, IFLASH_PAGE_SIZE);	// Clear shared_buffer
		}
	}
	else
	{
		// Once starting boundary has been handled, the start of each payload is valid
		px = payload;
	}
	
	// Search for ending boundary
	py = payload + len;
	
	i = 128;
	while(i>0)
	{
		py--;
		// Latch onto '----' ("----[boundary ID]")
		if((*(py-1)) == '\x2d' && (*(py-2)) == '\x2d' && (*(py-3)) == '\x2d' && (*(py-4)) == '\x2d')
		{
			// Store the discovered boundary
			char tmpID[BOUNDARY_MAX_LEN] = {0};
			int z = 0;
			while(z < BOUNDARY_MAX_LEN && *(py+z) != '\x2d' && *(py+z) != '\x0d' && *(py+z) != '\x0a')
			{
				tmpID[z] = *(py+z);
				z++;
			}
			
			TRACE("http.c: discovered boundary ID : %s", tmpID);
			
			// Match the boundary ID with stored ID
			if(strcmp(tmpID, boundary_ID) == 0)
			{
				TRACE("http.c: boundary IDs match");
				TRACE("http.c: moving data end pointer");
				// Traverse through the preceding newline characters
				while(*(py-1) == '\x0d' || *(py-1) == '\x0a' || *(py-1) == '\x2d')
				{
					py--;
				}
				
				i = 0;
				// 'i' will be decremented to -1 if this line is run
			}
			else
			{
				TRACE("http.c: boundary IDs do not match");
				i = 1;
				// 'i' will be decremented to 0 if this line is run
			}
		}
		i--;
	}

	
	if(i == 0)
	{
		TRACE("http.c: ending boundary not found - ending data is valid");
		
		// Return ending pointer to the end
		py = payload + len;
	}
	else
	{
		TRACE("http.c: ending boundary found");
		final = 1;
	}
	
	// Get length of uploaded part
	data_len = py - px;
	
	// Check if any existing data needs to be handled
	if(saved_bytes)
	{
		TRACE("http.c: %d saved bytes need to be cleared", saved_bytes);
		
		if(final)
		{
			/* Final page needs to be written */
			
			// Fill 512-byte array
			while(saved_bytes < IFLASH_PAGE_SIZE)
			{
				if(px < py)
				{
					// Write data
					page[saved_bytes] = *px;
					px++;
					handled_bytes++;
				}
				else
				{
					// Append 0xFF
					page[saved_bytes] = 0xFF;
				}

				saved_bytes++;
			}
			
			// Write data to page
			if(flash_write_page(&page))
			{
				TRACE("http.c: final firmware page written successfully");
				page_ctr++;
			}
			else
			{
				TRACE("http.c: final firmware page write FAILED");
			}
		}
		else if(saved_bytes + len < IFLASH_PAGE_SIZE)
		{
			int max_len = saved_bytes + len;
			// Fill existing partially-complete page with new data
			while(saved_bytes < max_len && handled_bytes < len)
			{
				page[saved_bytes] = *px;
				if(px < py)
				{
					px++;
				}
				else
				{
					TRACE("http.c: ERROR - multi-part start pointer has passed the end pointer");
				}
				saved_bytes++;
				handled_bytes++;
			}
			
			// Handle edge-case
			TRACE("http.c: unable to fill a complete page - skipping page write");
			TRACE("http.c: %d bytes saved", saved_bytes);
			
			total_handled_bytes += handled_bytes;
			return 1;
		}
		else
		{
			// Fill existing partially-complete page with new data
			while(saved_bytes < IFLASH_PAGE_SIZE && handled_bytes < len)
			{
				page[saved_bytes] = *px;
				if(px < py)
				{
					px++;
				}
				else
				{
					TRACE("http.c: ERROR - multi-part start pointer has passed the end pointer");
				}
				saved_bytes++;
				handled_bytes++;
			}
			
			// Write data to page
			if(flash_write_page(&page))
			{
				TRACE("http.c: firmware page written successfully");
				page_ctr++;
			}
			else
			{
				TRACE("http.c: firmware page write FAILED");
			}
		}
				
		// Saved bytes have been handled - clear the counter
		saved_bytes = 0;
		
		TRACE("http.c: saved bytes have been cleared");		
		TRACE("http.c: handled_bytes: %04d, data_len: %04d", handled_bytes, data_len);
	}

	while(handled_bytes < data_len)
	{
		if(data_len - handled_bytes >= IFLASH_PAGE_SIZE)
		{
			// Fill 512-byte array
			int j = 0;
			while(j < IFLASH_PAGE_SIZE)
			{
				page[j] = *px;
				if(px < py)
				{
					px++;	
				}
				else
				{
					TRACE("http.c: ERROR - multi-part start pointer has passed the end pointer");
				}
				j++;
				handled_bytes++;
			}
			
			// Write to page
			if(flash_write_page(&page))
			{
				TRACE("http.c: firmware page written successfully");
				page_ctr++;
			}
			else
			{
				TRACE("http.c: firmware page write FAILED");
			}
		}
		else if(!final)
		{
			/* Data needs to be saved */
			TRACE("http.c: data needs to be saved");
			
			// Save leftover into page array for next run-through
			int j = 0;
			while(handled_bytes < data_len)
			{
				page[j] = *px;
				if(px < py)
				{
					px++;
				}
				else
				{
					TRACE("http.c: ERROR - multi-part start pointer has passed the end pointer");
				}
				j++;
				handled_bytes++;
				saved_bytes++;
			}
			
			TRACE("http.c: %d bytes saved", saved_bytes);
		}
		else
		{
			/* Final page needs to be written */
			
			// Fill 512-byte array
			int j = 0;
			while(j < IFLASH_PAGE_SIZE)
			{
				if(px < py)
				{
					// Write data
					page[j] = *px;
					px++;
					handled_bytes++;
				}
				else
				{
					// Append 0xFF
					page[j] = 0xFF;
				}

				j++;
			}
			
			// Write to page
			if(flash_write_page(&page))
			{
				TRACE("http.c: final page written successfully");
				page_ctr++;
			}
			else
			{
				TRACE("http.c: final page write FAILED");
			}
		}
	
		TRACE("http.c: handled_bytes: %04d, data_len: %04d", handled_bytes, data_len);
	}	
	
	total_handled_bytes += handled_bytes;
	TRACE("http.c: total_handled_bytes: %d", total_handled_bytes);
	
	if(final)
	{		
		return 2;
	}
	else
	{
		return 1;
	}
}

static uint8_t Config_Network(char *payload, int len)
{
	int i = 0;
	char *pdat;
	payload[len] = '&';
	
	memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
	
	// Device Name
	pdat = strstr(payload, "wi_deviceName");	// Search for element
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
	pdat = strstr(payload, "wi_macAddress");
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
				return FAILURE;
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
	pdat = strstr(payload, "wi_ipAddress");
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
				return FAILURE;
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
	pdat = strstr(payload, "wi_netmask");
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
				return FAILURE;
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
	pdat = strstr(payload, "wi_gateway");
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
			return FAILURE;
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
	
	return SUCCESS;
	
	// Send updated header page (with restart button)
	
	// ***** Placeholder until frame refresh targeting is implemented
	//
	//
	//
}

/*
*	Create and format HTTP/HTML for frames
*
*/
static uint8_t interfaceCreate_Frames(void)
{
	// Format HTTP response
	sprintf(shared_buffer, http_header);
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
static uint8_t interfaceCreate_Header(void)
{
	int hr = (totaltime/2)/3600;
	int t = (totaltime/2)%3600;
	int min = t/60;

	// Send header
	sprintf(shared_buffer, http_header);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
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
						"<form action=\"btn_restart\" method=\"post\"  onsubmit=\"return confirm('Zodiac FX will now restart.');\" target=_top>"\
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

/*
*	Create and format HTML for menu page
*
*/
static uint8_t interfaceCreate_Menu(void)
{
	// Send menu
	sprintf(shared_buffer, http_header);

	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
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
						"<li id=\"sub\"><a href=\"upload.htm\" target=\"page\">Update f/w</a></li>"
						"<li><a href=\"d_home.htm\" target=\"page\">Display</a></li>"\
						"<li id=\"sub\"><a href=\"d_ports.htm\" target=\"page\">Ports</a></li>"\
						"<li id=\"sub\"><a href=\"d_of.htm\" target=\"page\">OpenFlow</a></li>"\
						"<li id=\"sub\"><a href=\"d_flo.htm\" target=\"page\">Flows</a></li>"\
						"<li id=\"sub\"><a href=\"d_meters.htm\" target=\"page\">Meters</a></li>"\
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
static uint8_t interfaceCreate_Home(void)
{	
	int hr = (totaltime/2)/3600;
	int t = (totaltime/2)%3600;
	int min = t/60;

	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<META http-equiv=\"refresh\" content=\"61\">"\
		"<html>"\
			"<head>"\
				"<style>"\
		);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
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
*	Create and format HTML for firmware update page
*
*/
static uint8_t interfaceCreate_Upload(void)
{
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
		);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h2>Firmware Update</h2>"\
				"</p>"\
			"<body>"\
				"<p>Browser firmware update supports official binaries (version 0.80 and later).<br><br>Please find the latest version in the <a href=\"http://forums.northboundnetworks.com/index.php?PHPSESSID=39c9227476da4ef211c9c3b1fa235951&topic=52.0\">forums</a>.</p>"\
				"<form action=\"upload\" method =\"post\" enctype=\"multipart/form-data\" onsubmit=\"return confirm('Firmware file will now be uploaded. This may take up to 60 seconds. DO NOT refresh the page while firmware update is in progress.');\">"\
					"<input type=\"file\" name =\"file\"><br><br>"\
					"<input type=\"submit\" value=\"Upload File\"/>"\
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
*	Create and format HTML for firmware update status page
*
*/
static uint8_t interfaceCreate_Upload_Status(uint8_t sel)
{
	if(sel == 1)
	{	
		snprintf(shared_buffer, SHARED_BUFFER_LEN,\
			"<!DOCTYPE html>"\
				"<html>"\
					"<head>"\
						"<style>"\
					);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"</style>"\
					"</head>"\
					"<body>"\
						"<p>"\
							"<h2>Firmware Update</h2>"\
						"</p>"\
					"<body>"\
						"<p>Firmware upload successful.<br><br>"\
						"Zodiac FX will be updated on the next restart.</p>"\
						"<form action=\"btn_restart\" method=\"post\"  onsubmit=\"return confirm('Zodiac FX will now restart.');\" target=_top>"\
							"<button name=\"btn\" value=\"btn_restart\">Restart</button>"\
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
	else
	{
		snprintf(shared_buffer, SHARED_BUFFER_LEN,\
			"<!DOCTYPE html>"\
				"<html>"\
					"<head>"\
						"<style>"\
				);
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"</style>"\
					"</head>"\
					"<body>"\
						"<p>"\
							"<h2>Firmware Update</h2>"\
						"</p>"\
					"<body>"\
				);
		if(sel == 2)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"<p>Firmware upload interrupted. Please try again.<br><br>"\
				);
		}
		else if(sel == 3)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"<p>Firmware upload failed. Unable to verify firmware. Please try again, or check the integrity of the firmware.<br><br>"\
				);
		}
		else if(sel == 4)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
			"<p>Firmware upload in progress. Please try again in 30 seconds.<br><br>"\
			);
		}
		else
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
			"<p>Firmware upload failed. Please try again.<br><br>"\
			);
		}
				
		if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
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
}

/*
*	Create and format HTML for display help page
*
*/
static uint8_t interfaceCreate_Display_Home(void)
{
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</style>"\
			"</head>"\
			"<body>"\
				"<h2>Display Help</h2>"\
				"<h3>Ports</h3>"\
					"<p>"\
						"View information for each of the Zodiac FX Ethernet ports, including its status, byte/packet statistics, and VLAN configuration."\
						"<br><br>Ports can be assigned to VLANs on this page."\
						"<br><br>Warning: incorrectly assigning VLANs may cause the web interface to be unresponsive. Zodiac FX may need to be re-configured through a terminal application."\
					"</p>"\
				"<h3>OpenFlow</h3>"\
					"<p>"\
						"View the current OpenFlow status and statistics."\
					"</p>"\
				"<h3>Flows</h3>"\
					"<p>"\
						"View the current flows in the flow table. 4 flows are displayed per page."\
					"</p>"\
				"<h3>Meters</h3>"\
					"<p>"\
						"View the current meters in the meter table. 3 meters are displayed per page. Up to 8 meters can be configured, with up to 3 meter bands each."\
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
static uint8_t interfaceCreate_Display_Ports(uint8_t step)
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
		snprintf(portvlType[0], 11, "n/a");
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
		
		sprintf(shared_buffer, http_header);

		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
			"<!DOCTYPE html>"\
			"<META http-equiv=\"refresh\" content=\"31\">"\
			"<html>"\
				"<head>"\
					"<style>"\
				);
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
					"table {"\
						"border-collapse: collapse;"\
						"border: 1px solid black;"\
					"}"\
					"td, th {"\
						"height: 27px;"\
						"padding-left: 7px;"\
						"padding-right: 10px;"\
						"border: 1px solid black;"\
						"white-space: nowrap;"\
					"}"\
					"th {"\
						"width: 75px;"\
					"}"\
					"#row {"\
						"font-weight: bold;"\
					"}"\
					"#label {"\
						"width: 180px;"\
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
						"<th id=\"label\"></th>"\
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
							"<input type=\"submit\" name=\"ports_submit\" value=\"Save\">"\
							"<input type=\"reset\" name=\"ports_cancel\" value=\"Cancel\"><br>"\
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
							"<input type=\"submit\" name=\"ports_submit\" value=\"Save\">"\
							"<input type=\"reset\" name=\"ports_cancel\" value=\"Cancel\"><br>"\
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
		TRACE("http.c: Display: Ports step error");
		return 0;
	}
}


/*
*	Create and format HTML for display openflow page
*
*/
static uint8_t interfaceCreate_Display_OpenFlow(void)
{
	
	// Status
	char wi_ofStatus[15] = "";
	
	if (tcp_con_state == 1 && tcp_pcb->state == ESTABLISHED && Zodiac_Config.OFEnabled == OF_ENABLED)
	{
		snprintf(wi_ofStatus, 15, "Connected");
	}
	else if (Zodiac_Config.OFEnabled == OF_DISABLED)
	{
		snprintf(wi_ofStatus, 15, "Disabled");
	}
	else
	{
		snprintf(wi_ofStatus, 15, "Disconnected");
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
	
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<META http-equiv=\"refresh\" content=\"31\">"\
		"<html>"\
			"<head>"\
				"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\

				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h2>OpenFlow Information</h2>"\
				"</p>"\
				"<form style=\"width: 200px\" action=\"save_none\" method=\"post\" onsubmit=\"return confirm('Zodiac FX needs to restart to apply changes. Press the restart button on the top right for your changes to take effect.');\">"\
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
static uint8_t interfaceCreate_Display_Flows(void)
{
	int i;
	uint8_t flowEnd = flowBase + FLOW_DISPLAY_LIMIT;
	struct ofp_action_header * act_hdr;

	// Ensure page correctly displays end of flows
	if(iLastFlow < flowEnd)
	{
		flowEnd = iLastFlow;
	}
	
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\

				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h2>Flows</h2>"\
					"%d flows installed<br>"\
			, iLastFlow);
			
	if(iLastFlow != 0)
	{
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"Showing flows %d - %d<br>"\
		, flowBase+1, flowEnd);
	}
	
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</p>"\
				"<pre><span style=\"font-size: 12px; line-height: 1\">"\
			);

// Begin Flow formatting
if (iLastFlow > 0)
{
	// OpenFlow v1.0 (0x01) Flow Table
	if( OF_Version == 1)
	{
		for (i=flowBase;i<flowEnd;i++)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n_______\r\n");
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n Flow %d\r\n",i+1);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Match:\r\n");
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
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"_______\r\n\n");
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

		for (i=flowBase;i<flowEnd;i++)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n_______\r\n");
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n Flow %d\r\n",i+1);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Match:\r\n");
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
				// Get a list of all instructions for this flow
				void *insts[8] = {0};
				inst_size = 0;
				while(inst_size < ofp13_oxm_inst_size[i]){
					struct ofp13_instruction *inst_ptr = (struct ofp13_instruction *)(ofp13_oxm_inst[i] + inst_size);
					insts[ntohs(inst_ptr->type)] = inst_ptr;
					inst_size += ntohs(inst_ptr->len);
				}
						
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r Instructions:\r\n");
						
				// Check for optional metering instruction
				if(insts[OFPIT13_METER] != NULL)						
				{
					struct ofp13_instruction_meter *inst_meter = insts[OFPIT13_METER];
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Meter: %d\r\n", ntohl(inst_meter->meter_id));
				}
						
				if(insts[OFPIT13_APPLY_ACTIONS] != NULL)
				{
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Apply Actions:\r\n");
					struct ofp13_action_header *act_hdr;
					act_size = 0;
					inst_actions = insts[OFPIT13_APPLY_ACTIONS];
					if (ntohs(inst_actions->len) == sizeof(struct ofp13_instruction_actions)) snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   DROP \r\n");	// No actions
					while (act_size < (ntohs(inst_actions->len) - sizeof(struct ofp13_instruction_actions)))
					{
						act_hdr = (struct ofp13_action_header*)((uintptr_t)inst_actions->actions + act_size);
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
				if(insts[OFPIT13_GOTO_TABLE] != NULL)
				{
					struct ofp13_instruction_goto_table *inst_goto_ptr;
					inst_goto_ptr = (struct ofp13_instruction_goto_table *) insts[OFPIT13_GOTO_TABLE];
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Goto Table: %d\r\n", inst_goto_ptr->table_id);
				}
				} else {
				// No instructions
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r Instructions:\r\n");
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"   DROP \r\n");
			}
		}
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"_______\r\n\n");
	}
	}
	
// End Flow formatting

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</span></pre>"\
				"<form action=\"btn_ofPage\" method=\"post\"><br>"\
	);
	
	// Check if "previous page" button needs to be created
	if(flowBase >= FLOW_DISPLAY_LIMIT)
	{
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
					"<button name=\"btn\" value=\"btn_ofPrev\">Previous</button>"\
				);
	}
	
	// Check if "next page" button needs to be created
	if(flowEnd < iLastFlow)
	{
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
					"<button name=\"btn\" value=\"btn_ofNext\">Next</button>"\
				);
	}

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</form>");
	
	// Check if "clear flows" button needs to be created
	if(iLastFlow > 0)
	{
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"<form action=\"btn_ofClear\" method=\"post\"  onsubmit=\"return confirm('All flows will be cleared. Do you wish to proceed?');\">"\
					"<br><button name=\"btn\" value=\"btn_ofClear\">Clear Flows</button>"\
				"</form>"\
		);
	}
	
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
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
*	Create and format HTML for display meters page
*
*/
static uint8_t interfaceCreate_Display_Meters(void)
{
	/* Prepare meter counters */
	
	// Check status of start of range
	if(meterBase >= iLastMeter)
	{
		meterBase = 0;
	}
	
	// Find number of meters
	int meterCount;
	if(meter_entry[0] == NULL)
	{
		meterCount = 0;
	}
	else
	{
		meterCount = iLastMeter;
	}
	
	// Find end of display range (exclusive) - meterBase indexes the start of the range
	int meterEnd;
	if(meterBase + METER_DISPLAY_LIMIT >= iLastMeter)
	{
		meterEnd = iLastMeter;
	}
	else
	{
		meterEnd = meterBase + METER_DISPLAY_LIMIT;
	}
	
	// Format header
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h2>Meters</h2>"\
					"%d meters configured<br>"\
			, meterCount);
			
	if(meterCount != 0)
	{
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"Showing meters %d - %d<br>"\
			, meterBase+1, meterEnd);
	}
	
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</p>"\
				"<pre><span style=\"font-size: 12px; line-height: 1\">"\
			);

// Begin Meter formatting
		
	// Check that table is populated
	if(meter_entry[0] != NULL)
	{
		int meter_index = meterBase;
		while(meter_entry[meter_index] != NULL && meter_index < meterEnd)
		{
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"_______\r\n");
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\nMeter %d\r\n", meter_index+1);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Meter ID: %d\r\n", meter_entry[meter_index]->meter_id);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"  Counters:\r\n");
			meter_entry[meter_index]->flow_count = get_bound_flows(meter_entry[meter_index]->meter_id);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\tBound Flows:\t%d\tDuration:\t%d sec\r\n", meter_entry[meter_index]->flow_count, (sys_get_ms()-meter_entry[meter_index]->time_added)/1000);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\tByte Count:\t%"PRIu64"\tPacket Count:\t%"PRIu64"\r\n", meter_entry[meter_index]->byte_in_count, meter_entry[meter_index]->packet_in_count);
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\tConfiguration:\t");
			if(((meter_entry[meter_index]->flags) & OFPMF13_KBPS) == OFPMF13_KBPS)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"KBPS; ");
			}
			if(((meter_entry[meter_index]->flags) & OFPMF13_PKTPS) == OFPMF13_PKTPS)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"PKTPS; ");
			}
			if(((meter_entry[meter_index]->flags) & OFPMF13_BURST) == OFPMF13_BURST)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"BURST; ");
			}
			if(((meter_entry[meter_index]->flags) & OFPMF13_STATS) == OFPMF13_STATS)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"STATS; ");
			}
			if(meter_entry[meter_index]->flags == 0)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer)," NONE;");
			}
				
			snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n\tNumber of bands:\t%d\r\n", meter_entry[meter_index]->band_count);
			int bands_processed = 0;
			struct ofp13_meter_band_drop * ptr_band;
			ptr_band = &(meter_entry[meter_index]->bands);
			while(bands_processed < meter_entry[meter_index]->band_count)
			{
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\t\tBand %d:\r\n", bands_processed+1);
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\t\t  Type:\t\t");
				if(ptr_band->type == OFPMBT13_DROP)
				{
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"DROP\r\n");
				}
				else if(ptr_band->type == OFPMBT13_DSCP_REMARK)
				{
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"DSCP REMARK (unsupported)\r\n");
				}
				else
				{
					snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"unsupported type\r\n");
				}
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\t\t  Rate:\t\t%d\t\r\n", ptr_band->rate);
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\t\t  Burst Size:\t%d\t\r\n", ptr_band->burst_size);
					
				// Find band index
				int band_index = ((uint8_t*)ptr_band - (uint8_t*)&(meter_entry[meter_index]->bands)) / sizeof(struct ofp13_meter_band_drop);
					
				// Display counters
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\t\t  Byte count:\t%"PRIu64"\t\r\n", band_stats_array[meter_index].band_stats[band_index].byte_band_count);
				snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\t\t  Packet count:\t%"PRIu64"\t\r\n", band_stats_array[meter_index].band_stats[band_index].packet_band_count);
					
				ptr_band++;	// Move to next band
				bands_processed++;
			}
			meter_index++;
		}
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),"\r\n_______\r\n\r\n");
	}
	
// End Meter formatting

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</span></pre>"\
				"<form action=\"btn_meterPage\" method=\"post\">"\
	);
	
	// Check if "previous page" button needs to be created
	if(meterBase >= METER_DISPLAY_LIMIT)
	{
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
					"<button name=\"btn\" value=\"btn_meterPrev\">Previous</button>"\
				);
	}
	
	// Check if "next page" button needs to be created
	if(meterEnd < iLastMeter)
	{
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
					"<button name=\"btn\" value=\"btn_meterNext\">Next</button>"\
				);
	}

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</form>");
		
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
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
static uint8_t interfaceCreate_Config_Home(void)
{
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</style>"\
			"</head>"\
			"<body>"\
				"<h2>Config Help</h2>"\
				"<h3>Network</h3>"\
					"<p>"\
						"Configure the network settings of the Zodiac FX. This includes the device name, IP address, MAC address, netmask, and default gateway. After saving a configuration, a restart is required for changes to take effect."\
					"</p>"\
				"<h3>VLANs</h3>"\
					"<p>"\
						"Configure Virtual LANs. These can be added or deleted as required. To assign a port to a VLAN, go to the Display: Ports page. A restart is required for changes to take effect."\
						"<br><br>Warning: incorrectly configuring VLANs may cause the web interface to be unresponsive. Zodiac FX may need to be re-configured through a terminal application."\
					"</p>"\
				"<h3>OpenFlow</h3>"\
					"<p>"\
						"Configure OpenFlow. Set the controller IP and port for your network configuration. OpenFlow failstate can be modified, and an OpenFlow version can be forced. Alternatively, OpenFlow may be disabled."\
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
static uint8_t interfaceCreate_Config_Network(void)
{
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
			"<html>"\
				"<head>"\
					"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
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
static uint8_t interfaceCreate_Config_VLANs(void)
{
	int x;
	int delRow = 0;
	char wi_vlType[10] = "";
	
	// Opening tags, and base table
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
			"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
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
static uint8_t interfaceCreate_Config_OpenFlow(void)
{	
	sprintf(shared_buffer, http_header);

	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h2>OpenFlow Configuration</h2>"\
				"</p>"\
				"<form style=\"width: 200px\" action=\"save_of\" method=\"post\" onsubmit=\"return confirm('Zodiac FX needs to restart to apply changes. Press the restart button on the top right for your changes to take effect.');\">"\
					"<fieldset>"\
						"<legend>OpenFlow</legend>"\
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
		
		snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
						"Controller IP:<br>"\
						"<input type=\"text\" name=\"wi_ofIP\" value=\"%d.%d.%d.%d\"><br><br>"\
						"Controller Port:<br>"\
						"<input type=\"text\" name=\"wi_ofPort\" value=\"%d\"><br><br>"\
				, Zodiac_Config.OFIP_address[0], Zodiac_Config.OFIP_address[1]
				, Zodiac_Config.OFIP_address[2], Zodiac_Config.OFIP_address[3]
				, Zodiac_Config.OFPort
			);
		
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
static uint8_t interfaceCreate_About(void)
{
	sprintf(shared_buffer, http_header);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</style>"\
			"</head>"\
			"<body>"\
				"<h2>About</h2>"\
				"<h3>Zodiac FX</h3>"\
					"<p>"\
						"The Zodiac FX was created by <a href=\"http://northboundnetworks.com\" target=\"_blank\">Northbound Networks</a> to allow the development of SDN applications on real hardware."\
					"</p>"\
/*				"<h3>What's new in v0.72</h3>"\
					"<p>"\
						"- Feature<br>"\
						"- Feature<br>"\
						"- Feature<br>"\
					"</p>"\		*/
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
*	Create and format HTML for interstitial restart page
*
*/
static uint8_t interfaceCreate_Restart(void)
{
	sprintf(shared_buffer, http_header);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
		"<!DOCTYPE html>"\
		"<META http-equiv=\"refresh\" content=\"10; url=frames.html\">"\
		"<html>"\
			"<head>"\
				"<style>"\
			);
	snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer), html_style_body);
	if( snprintf(shared_buffer+strlen(shared_buffer), SHARED_BUFFER_LEN-strlen(shared_buffer),\
				"</style>"\
			"</head>"\
			"<body>"\
					"<p>"\
						"Restarting..."\
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