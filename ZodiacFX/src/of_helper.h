/**
 * @file
 * of_helper.h
 *
 * This file contains the function declarations and structures for the OpenFlow helper functions
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


#ifndef OF_HELPER_H_
#define OF_HELPER_H_

#include "openflow.h"

#define VLAN_OFFSET(x, isVlanTag)       (isVlanTag ? (x + 4) : x)

struct packet_fields
{
        bool valid;
        bool isVlanTag;
	uint8_t *payload;
        uint16_t eth_prot;
        uint8_t ip_prot;
        uint16_t *vlanid;
        uint32_t *ip_src;
        uint32_t *ip_dst;
        uint16_t *tcp_src;
        uint16_t *tcp_dst;
};

int flowmatch10(uint8_t *pBuffer, int port);
int flowmatch13(uint8_t *pBuffer, int port, uint8_t table_id, struct packet_fields *fields);
int field_match10(struct ofp_match *match_a, struct ofp_match *match_b);
int field_match13(uint8_t *oxm_a, int len_a, uint8_t *oxm_b, int len_b);
void nnOF_timer(void);
void flow_timeouts(void);
void clear_flows(void);
int flow_stats_msg10(char *buffer, int first, int last);
int flow_stats_msg13(char *buffer, int first, int last);
void set_ip_checksum(uint8_t *p_uc_data, int packet_size, int iphdr_offset);
void remove_flow13(int flow_id);

#endif /* OF_HELPER_H_ */
