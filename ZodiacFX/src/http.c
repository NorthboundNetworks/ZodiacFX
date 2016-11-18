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
 * Author: Paul Zanna <paul@northboundnetworks.com>
 *
 */

#include <asf.h>
#include <string.h>
#include "http.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "timers.h"

#include "config_zodiac.h"

// External Variables
extern int totaltime;
extern int32_t ul_temp;

// Local Variables
struct tcp_pcb *http_pcb;
char http_buffer[512];
char output_buffer[256];
	
static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t http_accept(void *arg, struct tcp_pcb *pcb, err_t err);
void http_send(char *buffer, struct tcp_pcb *pcb);

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
	char *pc;

	
	if (err == ERR_OK && p != NULL)
	{
		tcp_recved(pcb, p->tot_len);
		pc = (char*)p->payload;
		len = p->tot_len;

		for(int i=0;i<len;i++) http_buffer[i] = pc[i];
		pbuf_free(p);
		
				int hr = (totaltime/2)/3600;
				int t = (totaltime/2)%3600;
				int min = t/60;
				int sec = t%60;
		
		// Format HTTP response
		sprintf(output_buffer,"HTTP/1.1 200 OK\r\n");
		strcat(output_buffer,"Connection: close\r\n");
		strcat(output_buffer,"Content-Type: text/html; charset=UTF-8\r\n\r\n");
		// Append web page
		strcat(output_buffer,"<!DOCTYPE html><html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><title>Zodiac FX</title><style type=\"text/css\">body {overflow: hidden;height: 100%; max-height: 100%; font-family:Sans-serif;line-height: 1.5em;font-size: 15px;}header {position: absolute;top: 0;left: 0;width: 100%;height: 70px; overflow: hidden;color: white;background: black;}h1, h2 {margin-top:15px;margin-bottom:10px;}main {position: fixed;top: 70px;left: 230px; right: 0;bottom: 0;margin: 20px;overflow: auto;}/* Branding/logo padding */#logo {padding-left: 20px;padding-top: 10px;}/* Sidebar class style */.sidebar {position: absolute; top: 70px; left: 0; bottom: 0;width: 180px;padding: 20px;overflow: auto;background: #F6F6F6; }/* List style in sidebar */.sidebar ul {list-style-type: none;margin: 10px;padding: 0;}/* Link style in sidebar list */.sidebar ul a {color: black;text-decoration: none;}/* Selected link style in sidebar list */.sidebar ul a:active {font-weight: bold;}</style></head><body><header><h1 id=\"logo\">Zodiac FX</h1></header><main>");
		// Insert data onto page
						sprintf(output_buffer + strlen(output_buffer),"<h1>Device Status</h1>");
						sprintf(output_buffer + strlen(output_buffer)," <p><br>Firmware Version: %s<br>",VERSION);
						sprintf(output_buffer + strlen(output_buffer)," CPU Temp: %d C<br>", (int)ul_temp);
						sprintf(output_buffer + strlen(output_buffer)," Uptime: %02d:%02d:%02d", hr, min, sec);
		
		strcat(output_buffer,"</main><div class=\"sidebar\"><h2>Base</h2><ul><li><a href=\"#\">Show Status</a></li><li><a href=\"#\">Show Ports</a></li><li><a href=\"#\">Show Version</a></li><li><a href=\"#\">Help</a></li></ul><h2>Config</h2><ul><li><a href=\"#\">Save</a></li><li><a href=\"#\">Show Config</a></li><li><a href=\"#\">Show VLANs</a></li><li><a href=\"#\">Set Name</a></li><li><a href=\"#\">Set MAC Address</a></li><li><a href=\"#\">Set IP Address</a></li><li><a href=\"#\">Set Netmask</a></li><li><a href=\"#\">Set Gateway</a></li><li><a href=\"#\">Set OF-Controller</a></li><li><a href=\"#\">Set OF-Port</a></li><li><a href=\"#\">Set OF-Version</a></li><li><a href=\"#\">Add VLAN</a></li><li><a href=\"#\">Delete VLAN</a></li><li><a href=\"#\">Set VLAN-Type</a></li><li><a href=\"#\">Add VLAN-Port</a></li><li><a href=\"#\">Delete VLAN-Port</a></li><li><a href=\"#\">Factory Reset</a></li></ul><h2>OpenFlow</h2><ul><li><a href=\"#\">Show Status</a></li><li><a href=\"#\">Show Flows</a></li><li><a href=\"#\">Enable</a></li><li><a href=\"#\">Disable</a></li></ul><h2>Debug</h2><ul><li><a href=\"#\">Read from Register</a></li><li><a href=\"#\">Write to Register</a></li></ul></div></body></html>");
		
		// Send HTTP response
		http_send(&output_buffer, pcb);
		
	} else {
		pbuf_free(p);
	}

	if (err == ERR_OK && p == NULL)
	{
		tcp_close(pcb);
	}

	return ERR_OK;
}

/*
*	HTTP Send function
*
*/
void http_send(char *buffer, struct tcp_pcb *pcb)
{
	int len = strlen(buffer);
	//tcp_sent(pcb,NULL);
	err_t err = tcp_write(pcb, buffer, len, TCP_WRITE_FLAG_COPY);
	if (err == ERR_OK) tcp_output(pcb);
	tcp_close(pcb);
	return;
}
