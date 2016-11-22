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
#include "openflow/openflow.h"
#include "trace.h"

#include "config_zodiac.h"

// External Variables
extern int totaltime;
extern int32_t ul_temp;

// Local Variables
struct tcp_pcb *http_pcb;
char http_buffer[512];		// Buffer for HTTP message storage
char http_msg[64];
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];

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
	int i = 0;
	char *pc;
	memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
	
	if (err == ERR_OK && p != NULL)
	{
		tcp_recved(pcb, p->tot_len);
		pc = (char*)p->payload;
		len = p->tot_len;

		for(i;i<len;i++) http_buffer[i] = pc[i];
		pbuf_free(p);
		
		// Check HTTP method
		i = 0;
		while(i < 63 && (http_buffer[i] != ' '))
		{
			http_msg[i] = http_buffer[i];
			i++;
		}
	
		if(strcmp(http_msg,"GET") == 0)
		{
			TRACE("http.c: GET method received")
			
			memset(&http_msg, 0, sizeof(http_msg));	// Clear HTTP message array
			
			// Specified resource directly follows GET
			i = 0;
			while(i < 63 && (http_buffer[i+5] != ' '))
			{
				http_msg[i] = http_buffer[i+5];	// Offset http_buffer to isolate resource
				i++;
			}
			
			// Check resource
			if(http_msg[0] == '\0')
			{
				// Format HTTP response
				sprintf(shared_buffer,"HTTP/1.1 200 OK\r\n");
				strcat(shared_buffer,"Connection: close\r\n");
				strcat(shared_buffer,"Content-Type: text/html; charset=UTF-8\r\n\r\n");
				// Send frames
				strcat(shared_buffer, "<html><head><title>Zodiac FX</title></head>\
						<frameset rows=\"100,*\"><frame src=\"header.htm\" name=\"topframe\" noresize scrolling=\"no\" marginwidth=\"0\" marginheight=\"0\" framespacing=\"0\" frameborder=\"1\"><frameset cols=\"180, *\">\
						<frameset rows=\"*,80\" framespacing=\"0\" border=\"0\"><frame src=\"menu.htm\" name=\"contents\" noresize frameborder=\"1\" marginwidth=\"0\" marginheight=\"0\" scrolling=\"auto\"></frameset>\
						<frame src=\"body.htm\" name=\"formframe\" frameborder=\"1\" marginwidth=\"0\" marginheight=\"0\" scrolling=\"auto\"></frameset><noframes><body><p>Browser version not supported.\
						</body></noframes></frameset></html>");
			}
			else if(strcmp(http_msg,"header.htm") == 0)
			{
				// Format HTTP response
				sprintf(shared_buffer,"HTTP/1.1 200 OK\r\n");
				strcat(shared_buffer,"Connection: close\r\n");
				strcat(shared_buffer,"Content-Type: text/html; charset=UTF-8\r\n\r\n");
				// Send header
				sprintf(shared_buffer,"<html><head><style>header {font-family:Sans-serif;position: absolute;top: 0;left: 0;width: 100%;height: 100%;overflow: hidden;color: white;background: black;}\
						h1{margin-top:30px;padding-left: 40px;}</style></head><body><header><h1>Zodiac FX</h1></header></body></html>");
			}
			else if(strcmp(http_msg,"menu.htm") == 0)
			{
				// Format HTTP response
				sprintf(shared_buffer,"HTTP/1.1 200 OK\r\n");
				strcat(shared_buffer,"Connection: close\r\n");
				strcat(shared_buffer,"Content-Type: text/html; charset=UTF-8\r\n\r\n");
				// Send header
				sprintf(shared_buffer,"<body><main><h1>Menu</h1><li>list</li><li>list</li></main></body>");
			}
			else if(strcmp(http_msg,"body.htm") == 0)
			{
				// Format HTTP response
				sprintf(shared_buffer,"HTTP/1.1 200 OK\r\n");
				strcat(shared_buffer,"Connection: close\r\n");
				strcat(shared_buffer,"Content-Type: text/html; charset=UTF-8\r\n\r\n");
				// Send header
				sprintf(shared_buffer,"<body><main><h1>Web Interface</h1><p>This file serves as an interface guide for the Zodiac FX web interface.</p></main></body>");
			}
		}
		else if(strcmp(http_msg,"POST") == 0)
		{
			TRACE("http.c: POST method received")
		}
		else
		{
			TRACE("http.c: Unknown HTTP method received")
		}
			
		
				//int hr = (totaltime/2)/3600;
				//int t = (totaltime/2)%3600;
				//int min = t/60;
				//int sec = t%60;
				
		// Insert data onto page
						//sprintf(shared_buffer + strlen(shared_buffer),"<h1>Device Status</h1>");
						//sprintf(shared_buffer + strlen(shared_buffer)," <p><br>Firmware Version: %s<br>",VERSION);
						//sprintf(shared_buffer + strlen(shared_buffer)," CPU Temp: %d C<br>", (int)ul_temp);
						//sprintf(shared_buffer + strlen(shared_buffer)," Uptime: %02d:%02d:%02d", hr, min, sec);

		// Send HTTP response
		http_send(&shared_buffer, pcb);
		
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
