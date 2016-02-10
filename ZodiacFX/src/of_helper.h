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

int flowmatch10(const char *pBuffer, uint32_t port);
int flowmatch13(const char *pBuffer, uint32_t port);
int field_match10(struct ofp_match *match_a, struct ofp_match *match_b);
void nnOF_timer(void);
void flow_timeouts(void);
void clear_flows(void);
int flow_stats_msg10(char *buffer, int first, int last);
int flow_stats_msg13(char *buffer, int first, int last);
void set_ip_checksum(char *p_uc_data, int packet_size, int iphdr_offset);

// --- kwi ---

uint16_t fill_ofp13_flow_stats(const struct ofp13_flow_stats_request*, int*, char*, uint16_t);

#endif /* OF_HELPER_H_ */