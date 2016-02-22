/**
 * @file
 * openflow_10.c
 *
 * This file contains the OpenFlow v1.0 (0x01) specific functions
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
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "of_helper.h"
#include "lwip/tcp.h"
#include "ipv4/lwip/ip.h"
#include "lwip/tcp_impl.h"
#include "lwip/udp.h"

// Global variables
extern struct zodiac_config Zodiac_Config;
extern int iLastFlow;
extern int OF_Version;

/*
*	Converts a 64bit value from host to network format
*
*	@param n - value to convert.
*
*/
static inline uint64_t (htonll)(uint64_t n)
{
	return htonl(1) == 1 ? n : ((uint64_t)htonl(n) << 32) | htonl(n >> 32);
}

int match_frame_by_tuple(const struct fx_packet *packet, const struct fx_packet_oob *oob, const struct ofp_match tuple){
	return 0; // TODO
}

void execute_ofp10_flow(struct fx_packet *packet, struct fx_packet_oob *oob, int flow){
	return; // TODO
}
