/**
 * @file
 * telnet.c
 *
 * This file contains the telnet functions
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
#include <stdlib.h>
#include <inttypes.h>
#include "config_zodiac.h"
#include "command.h"
#include "conf_eth.h"
#include "eeprom.h"
#include "switch.h"
#include "openflow.h"
#include "of_helper.h"
#include "lwip/def.h"
#include "timers.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

// Global variables
extern struct zodiac_config Zodiac_Config;

// Local Variables
bool tshowintro = true;
uint8_t TelnetContext = 0;
struct tcp_pcb *telnet_pcb;
char telnet_buffer[64];		// Buffer for incoming telnet commands
char print_buffer[512];

static err_t telnet_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t telnet_accept(void *arg, struct tcp_pcb *pcb, err_t err);
void tprintf(char *buffer, struct tcp_pcb *pcb);
void tprintintro(struct tcp_pcb *pcb);
void tprinthelp(struct tcp_pcb *pcb);

void tcommand_root(char *command, char *param1, char *param2, char *param3);
void tcommand_config(char *command, char *param1, char *param2, char *param3);
void tcommand_openflow(char *command, char *param1, char *param2, char *param3);
void tcommand_debug(char *command, char *param1, char *param2, char *param3);

void telnet_init(void)
{
	telnet_pcb = tcp_new();
	tcp_bind(telnet_pcb, IP_ADDR_ANY, 23);
	telnet_pcb = tcp_listen(telnet_pcb);
	tcp_accept(telnet_pcb, telnet_accept);
}

static err_t telnet_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	LWIP_UNUSED_ARG(arg);
	LWIP_UNUSED_ARG(err);
	tcp_setprio(pcb, TCP_PRIO_NORMAL);
	tcp_recv(pcb, telnet_recv);
	tcp_err(pcb, NULL);
	tcp_poll(pcb, NULL, 4);
	return ERR_OK;
}

static err_t telnet_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	int i;
	int len;
	char *pc;
	char *command;
	char *param1;
	char *param2;
	char *param3;
	char *pch;

	if (err == ERR_OK && p != NULL)
	{
		tcp_recved(pcb, p->tot_len);
		pc = (char*)p->payload;
		len = p->tot_len;

		for(i=0;i<len;i++)
		{
			telnet_buffer[i] = pc[i];
		}
		pbuf_free(p);
		len = len -2;
		telnet_buffer[len] = '\0';
		pch = strtok (telnet_buffer," ");
		command = pch;
		pch = strtok (NULL, " ");
		param1 = pch;
		pch = strtok (NULL, " ");
		param2 = pch;
		pch = strtok (NULL, " ");
		param3 = pch;

		if (tshowintro == true)	// Show the intro only on the first key press
		{
			//tprintintro(pcb);
			tshowintro = false;
		}

		switch(TelnetContext)
		{
			case CLI_ROOT:
			tcommand_root(command, param1, param2, param3);
			break;

			case CLI_CONFIG:
			tcommand_config(command, param1, param2, param3);
			break;

			case CLI_OPENFLOW:
			tcommand_openflow(command, param1, param2, param3);
			break;

			case CLI_DEBUG:
			tcommand_debug(command, param1, param2, param3);
			break;
		};

		switch(TelnetContext)
		{
			case CLI_ROOT:
			sprintf(print_buffer, "%s# ",Zodiac_Config.device_name);
			tprintf(&print_buffer, pcb);
			print_buffer[0] = '\0';
			break;

			case CLI_CONFIG:
			sprintf(print_buffer, "%s(config)# ",Zodiac_Config.device_name);
			tprintf(&print_buffer, pcb);
			print_buffer[0] = '\0';
			break;

			case CLI_OPENFLOW:
			sprintf(print_buffer, "%s(openflow)# ",Zodiac_Config.device_name);
			tprintf(&print_buffer, pcb);
			print_buffer[0] = '\0';
			break;

			case CLI_DEBUG:
			sprintf(print_buffer, "%s(debug)# ",Zodiac_Config.device_name);
			tprintf(&print_buffer, pcb);
			print_buffer[0] = '\0';
			break;
		};

		} else {
		pbuf_free(p);
	}

	if (err == ERR_OK && p == NULL)
	{
		tcp_close(pcb);
	}

	return ERR_OK;
}

void tprintf(char *buffer, struct tcp_pcb *pcb)
{
	int len = strlen(buffer);
	//tcp_sent(pcb,NULL);
	err_t err = tcp_write(pcb, buffer, len, TCP_WRITE_FLAG_COPY);
	if (err == ERR_OK) tcp_output(pcb);
	return;
}

/*
*	Commands within the root context
*
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void tcommand_root(char *command, char *param1, char *param2, char *param3)
{
	// Change context
	if (strcmp(command, "config")==0){
		TelnetContext = CLI_CONFIG;
		return;
	}

	if (strcmp(command, "openflow")==0){
		TelnetContext = CLI_OPENFLOW;
		return;
	}

	if (strcmp(command, "debug")==0){
		TelnetContext = CLI_DEBUG;
		return;
	}

	// Display help
	if (strcmp(command, "help") == 0)
	{
		//tprinthelp();
		return;

	}

}


/*
*	Commands within the config context
*
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void tcommand_config(char *command, char *param1, char *param2, char *param3)
{
	// Return to root context
	if (strcmp(command, "exit")==0){
		TelnetContext = CLI_ROOT;
		return;
	}

	// Display help
	if (strcmp(command, "help") == 0)
	{
		//tprinthelp();
		return;

	}
}


/*
*	Commands within the OpenFlow context
*
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void tcommand_openflow(char *command, char *param1, char *param2, char *param3)
{
	if (strcmp(command, "exit")==0){
		TelnetContext = CLI_ROOT;
		return;
	}

	// Display help
	if (strcmp(command, "help") == 0)
	{
		//tprinthelp();
		return;

	}
}


/*
*	Commands within the debug context
*
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void tcommand_debug(char *command, char *param1, char *param2, char *param3)
{
	if (strcmp(command, "exit")==0){
		TelnetContext = CLI_ROOT;
		return;
	}

	// Display help
	if (strcmp(command, "help") == 0)
	{
		//tprinthelp();
		return;
	}

	if (strcmp(command, "restart")==0)
	{
		rstc_start_software_reset(RSTC);
		while (1);
	}
}


/*
*	Print the intro screen
*	ASCII art generated from http://patorjk.com/software/taag/
*
*/
void tprintintro(struct tcp_pcb *pcb)
{
// 	sprintf(print_buffer,"\r\n");
// 	strcat(buffer," _____             ___               _______  __\r\n");
// 	strcat(buffer,"/__  /  ____  ____/ (_)___ ______   / ____/ |/ /\r\n");
// 	strcat(buffer,"  / /  / __ \\/ __  / / __ `/ ___/  / /_   |   /\r\n");
// 	strcat(buffer," / /__/ /_/ / /_/ / / /_/ / /__   / __/  /   |  \r\n");
// 	strcat(buffer,"/____/\\____/\\__,_/_/\\__,_/\\___/  /_/    /_/|_| \r\n");
// 	strcat(buffer,"\t    by Northbound Networks\r\n");
// 	strcat(buffer,"\r\n\n");
// 	strcat(print_buffer,"Type 'help' for a list of available commands\r\n");

	sprintf(print_buffer, "*********");
	tprintf(&print_buffer, pcb);
	print_buffer[0] = '\0';
	return;
}

/*
*	Print a list of available commands
*
*
*/
void tprinthelp(struct tcp_pcb *pcb)
{
// 	sprintf(buffer,"\r\n");
// 	strcat(buffer,"The following commands are currently available:\r\n");
// 	strcat(buffer,"\r\n");
// 	strcat(buffer,"Base:\r\n");
// 	strcat(buffer," config\r\n");
// 	strcat(buffer," openflow\r\n");
// 	strcat(buffer," debug\r\n");
// 	strcat(buffer," show ports\r\n");
// 	strcat(buffer," show status\r\n");
// 	strcat(buffer," show version\r\n");
// 	strcat(buffer,"\r\n");
// 	strcat(buffer,"Config:\r\n");
// 	strcat(buffer," save\r\n");
// 	strcat(buffer," show config\r\n");
// 	strcat(buffer," show vlans\r\n");
// 	strcat(buffer," set name <name>\r\n");
// 	strcat(buffer," set mac-address <mac address>\r\n");
// 	strcat(buffer," set ip-address <ip address>\r\n");
// 	strcat(buffer," set netmask <netmasks>\r\n");
// 	strcat(buffer," set gateway <gateway ip address>\r\n");
// 	strcat(buffer," set of-controller <openflow controller ip address>\r\n");
// 	strcat(buffer," set of-port <openflow controller tcp port>\r\n");
// 	strcat(buffer," set failstate <secure|safe>\r\n");
// 	strcat(buffer," add vlan <vlan id> <vlan name>\r\n");
// 	strcat(buffer," delete vlan <vlan id>\r\n");
// 	strcat(buffer," set vlan-type <openflow|native>\r\n");
// 	strcat(buffer," add vlan-port <vlan id> <port>\r\n");
// 	strcat(buffer," delete vlan-port <port>\r\n");
// 	strcat(buffer," factory reset\r\n");
// 	strcat(buffer," set of-version <version(0|1|4)>\r\n");
// 	strcat(buffer," exit\r\n");
// 	strcat(buffer,"\r\n");
// 	strcat(buffer,"OpenFlow:\r\n");
// 	strcat(buffer," show status\r\n");
// 	strcat(buffer," show flows\r\n");
// 	strcat(buffer," show tables\r\n");
// 	strcat(buffer," enable\r\n");
// 	strcat(buffer," disable\r\n");
// 	strcat(buffer," clear flows\r\n");
// 	strcat(buffer," exit\r\n");
// 	strcat(buffer,"\r\n");
// 	strcat(buffer,"Debug:\r\n");
// 	strcat(buffer," read <register>\r\n");
// 	strcat(buffer," write <register> <value>\r\n");
// 	strcat(buffer," mem\r\n");
// 	strcat(buffer," trace\r\n");
// 	strcat(buffer," exit\r\n");
// 	strcat(buffer,"\r\n");
	return;
}
