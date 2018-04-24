/**
 * @file
 * command.h
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
 *
 */

#ifndef COMMANDS_H_
#define COMMANDS_H_

#include "config_zodiac.h"
#include "lwip/err.h"
#include <arch/cc.h>

enum of_status{
	OF_DISABLED,
	OF_ENABLED
	};

enum cli_context{
	CLI_ROOT,
	CLI_CONFIG,
	CLI_OPENFLOW,
	CLI_DEBUG
	};

PACK_STRUCT_BEGIN
struct virtlan {
	int uVlanID;
	char cVlanName[16];
	int uVlanType;
	int uTagged;
	uint8_t portmap[4];		// If the port is assigned to this VLAN
	int uActive;
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

PACK_STRUCT_BEGIN
struct zodiac_config {
	char device_name[16];
	uint8_t MAC_address[6];
	uint8_t IP_address[4];
	uint8_t netmask[4];
	uint8_t gateway_address[4];
	uint8_t OFIP_address[4];
	int OFPort;
	int OFEnabled;
	struct virtlan vlan_list[MAX_VLANS];
	uint8_t of_port[4];		// If the port is assigned to a VLAN
	uint8_t failstate;
	uint8_t of_version;
	uint8_t ethtype_filter;
	uint8_t stats_interval;
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

typedef struct arp_header {
	uint8_t et_dest[6];  /**< Destination node */
	uint8_t et_src[6];   /**< Source node */
	uint16_t et_protlen; /**< Protocol or length */
	uint16_t ar_hrd;   /**< Format of hardware address */
	uint16_t ar_pro;   /**< Format of protocol address */
	uint8_t ar_hln;    /**< Length of hardware address */
	uint8_t ar_pln;    /**< Length of protocol address */
	uint16_t ar_op;    /**< Operation */
	uint8_t ar_sha[6]; /**< Sender hardware address */
	uint8_t ar_spa[4]; /**< Sender protocol address */
	uint8_t ar_tha[6]; /**< Target hardware address */
	uint8_t ar_tpa[4]; /**< Target protocol address */
} arp_header_t, *p_arp_header_t;


void task_command(char *str, char * str_last);
void loadConfig(void);
void software_reset(void);

#endif /* COMMANDS_H_ */
