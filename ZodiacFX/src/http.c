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
#include "openflow/openflow.h"
#include "trace.h"
#include "command.h"

#include "config_zodiac.h"

// External Variables
extern int totaltime;
extern int32_t ul_temp;
extern struct zodiac_config Zodiac_Config;

// Local Variables
struct tcp_pcb *http_pcb;
char http_msg[64];			// Buffer for HTTP message filtering
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];

static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t http_accept(void *arg, struct tcp_pcb *pcb, err_t err);
void http_send(char *buffer, struct tcp_pcb *pcb);

uint8_t interfaceCreate_Frames(void);
uint8_t interfaceCreate_Header(void);
uint8_t interfaceCreate_Menu(void);
uint8_t interfaceCreate_Home(void);
uint8_t interfaceCreate_Config(void);
uint8_t interfaceCreate_OpenFlow(void);
uint8_t interfaceCreate_About(void);

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
		TRACE("http.c: %s method received", http_msg)
	
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
					http_send(&shared_buffer, pcb);
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
					http_send(&shared_buffer, pcb);
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
					http_send(&shared_buffer, pcb);
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
					http_send(&shared_buffer, pcb);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
      		else if(strcmp(http_msg,"config.htm") == 0)
			{
				if(interfaceCreate_Config())
				{
					http_send(&shared_buffer, pcb);
					TRACE("http.c: Page sent successfully - %d bytes", strlen(shared_buffer));
				}
				else
				{
					TRACE("http.c: Unable to serve page - buffer at %d bytes", strlen(shared_buffer));
				}
			}
      		else if(strcmp(http_msg,"openflow.htm") == 0)
			{
				if(interfaceCreate_OpenFlow())
				{
					http_send(&shared_buffer, pcb);
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
					http_send(&shared_buffer, pcb);
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
				pdat = strstr(http_payload, "w_deviceName");	// Search for element
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("w_deviceName")+1);	// Data format: w_deviceName=(name)
					
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
						//uint8_t namelen = strlen(pdat);
						//if (namelen > 15 ) namelen = 15; // Make sure name is less then 16 characters
						//sprintf(Zodiac_Config.device_name, pdat, namelen);
						//TRACE("Device name set to '%s'\r\n",Zodiac_Config.device_name);
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
				pdat = strstr(http_payload, "w_macAddress");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("w_macAddress")+1);	// Data format: w_deviceName=(name)
					
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
						
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
				pdat = strstr(http_payload, "w_ipAddress");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("w_ipAddress")+1);	// Data format: w_deviceName=(name)
									
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
										
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
				pdat = strstr(http_payload, "w_netmask");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("w_netmask")+1);	// Data format: w_deviceName=(name)
									
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
					if(pdat[i+1] == 'w')
					{
										
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
				pdat = strstr(http_payload, "w_gateway");
				if(pdat != NULL)	// Check that element exists
				{
					pdat += (strlen("w_gateway")+1);	// Data format: w_deviceName=(name)
									
					i = 0;
					while(i < 63 && (pdat[i] != '&') && (pdat[i] >= 31) && (pdat[i] <= 122))
					{
						http_msg[i] = pdat[i];	// Store value of element
						i++;
					}
				}
				else
				{
					TRACE("http.c: no gateway address found");
				}
				
				
				// SAVE TO EEPROM!
				// .
				// .
				
			}
			else
			{
				TRACE("http.c: unknown request: \"%s\"", http_msg);
			}
		}
		else
		{
			TRACE("http.c: WARNING: unknown HTTP method received")
		}
				
	}

	pbuf_free(p);

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
		TRACE("http.c: WARNING: html truncated to prevent buffer overflow");
		return 0;
	}
}

/*
*	Create and format HTML for header
*
*/
uint8_t interfaceCreate_Header(void)
{
	int hr = (totaltime/2)/3600;
	int t = (totaltime/2)%3600;
	int min = t/60;

	// Send header
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
                	"p {"\
						"font-family:Sans-serif;"\
						"color: white;"\
						"position: fixed;"\
						"right: 150px;"\
						"top: -5px;"\
					"}"\
				"</style>"\
				"</head>"\
				"<body>"\
					"<header>"\
						"<h1>Zodiac FX</h1>"\
					"</header>"\
                	"<p>"\
						"Firmware Version: %s<br>"\
						"CPU Temp: %d C<br>"\
						"Uptime: %02d:%02d"\
					"</p>"\
				"</body>"\
			"</html>"\
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
				"</style>"\
			"</head>"\
				"<body>"\
					"<ul>"\
						"<li><a href=\"home.htm\" target=\"page\">Home</a></li>"\
						"<li><a href=\"config.htm\" target=\"page\">Config</a></li>"\
						"<li><a href=\"openflow.htm\" target=\"page\">OpenFlow</a></li>"\
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
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
		"<!DOCTYPE html>"\
		"<html>"\
			"<head>"\
				"<style>"\
					"body {"\
						"overflow: auto;"\
						"font-family:Sans-serif;"\
						"font-size: 18px;"\
						"margin-left: 20px;"\
					"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
				"Home Page<br>Placedholder text."\
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
*	Create and format HTML for config page
*
*/
uint8_t interfaceCreate_Config(void)
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
						"font-size: 18px;"\
						"margin-left: 20px;"\
					"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
					"<h1>Configuration</h1>"\
				"</p>"\
				"<form action=\"save_config\" method=\"post\" onsubmit=\"return confirm('Zodiac FX needs to restart to apply changes. Press the restart button on the top right for your changes to take effect.');\">"\
					"<fieldset>"\
					"<legend>Connection:</legend>"\
						"Name:<br>"\
						"<input type=\"text\" name=\"w_deviceName\" value=\"%s\"><br><br>"\
						"MAC Address:<br>"\
						"<input type=\"text\" name=\"w_macAddress\" value=\"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\"><br><br>"\
						"IP Address:<br>"\
						"<input type=\"text\" name=\"w_ipAddress\" value=\"%d.%d.%d.%d\"><br><br>"\
						"Netmask:<br>"\
						"<input type=\"text\" name=\"w_netmask\" value=\"%d.%d.%d.%d\"><br><br>"\
						"Gateway:<br>"\
						"<input type=\"text\" name=\"w_gateway\" value=\"%d.%d.%d.%d\"><br><br>"\
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
*	Create and format HTML for openflow page
*
*/
uint8_t interfaceCreate_OpenFlow(void)
{
	if( snprintf(shared_buffer, SHARED_BUFFER_LEN,\
	"<!DOCTYPE html>"\
	"<html>"\
		"<head>"\
			"<style>"\
				"body {"\
					"overflow: auto;"\
					"font-family:Sans-serif;"\
					"font-size: 18px;"\
					"margin-left: 20px;"\
				"}"\
			"</style>"\
		"</head>"\
		"<body>"\
			"<p>"\
			"OpenFlow Page<br>Placedholder text."\
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
						"font-size: 18px;"\
						"margin-left: 20px;"\
					"}"\
				"</style>"\
			"</head>"\
			"<body>"\
				"<p>"\
				"About Page<br>Placedholder text."\
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