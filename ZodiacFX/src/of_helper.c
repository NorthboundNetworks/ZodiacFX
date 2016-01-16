/**
 * @file
 * of_helper.c
 *
 * This file contains the main OpenFlow helper functions
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
#include "config_zodiac.h"
#include "openflow.h"
#include "of_helper.h"
#include "lwip/tcp.h"
#include "switch.h"

// Global variables
extern int iLastFlow;
extern struct ofp_flow_mod flow_match[MAX_FLOWS];
extern struct flows_counter flow_counters[MAX_FLOWS];
extern int totaltime;
extern struct flow_tbl_actions flow_actions[MAX_FLOWS];
extern struct table_counter table_counters;

static uint16_t VLAN_VID_MASK = 0x0fff;

static inline uint64_t (htonll)(uint64_t n)
{
	return HTONL(1) == 1 ? n : ((uint64_t) HTONL(n) << 32) | HTONL(n >> 32);
}

/*
*	OpenFlow house keeping timer function.
*	Calls the port stat update functions.
*	Processes timeouts for flows.
*
*/
void nnOF_timer(void)
{
	totaltime++;
	update_port_stats();
	update_port_status();
	
	// Check flow timeouts
	int i;
	for (i=0;i<iLastFlow;i++)
	{
		if (flow_counters[i].active == true) // Make sure its an active flow
		{
			if (flow_match[i].idle_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && (totaltime - flow_counters[i].lastmatch) >= ntohs(flow_match[i].idle_timeout))
			{
				if (flow_match[i].flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(i,OFPRR_IDLE_TIMEOUT);
				// Clear flow counters and actions
				memset(&flow_counters[i], 0, sizeof(struct flows_counter));
				memset(&flow_actions[i], 0, sizeof(struct flow_tbl_actions));
				// Copy the last flow to here to fill the gap
				memcpy(&flow_match[i], &flow_match[iLastFlow-1], sizeof(struct ofp_flow_mod));
				memcpy(&flow_actions[i], &flow_actions[iLastFlow-1], sizeof(struct flow_tbl_actions));
				memcpy(&flow_counters[i], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
				// Clear the counters and action from the last flow that was moved
				memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
				memset(&flow_actions[iLastFlow-1], 0, sizeof(struct flow_tbl_actions));
				iLastFlow --;
				return;
			}
			
			if (flow_match[i].hard_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && (totaltime - flow_counters[i].duration) >= ntohs(flow_match[i].hard_timeout))
			{
				if (flow_match[i].flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(i,OFPRR_HARD_TIMEOUT);
				// Clear flow counters and actions
				memset(&flow_counters[i], 0, sizeof(struct flows_counter));
				memset(&flow_actions[i], 0, sizeof(struct flow_tbl_actions));
				// Copy the last flow to here to fill the gap
				memcpy(&flow_match[i], &flow_match[iLastFlow-1], sizeof(struct ofp_flow_mod));
				memcpy(&flow_actions[i], &flow_actions[iLastFlow-1], sizeof(struct flow_tbl_actions));
				memcpy(&flow_counters[i], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
				// Clear the counters and action from the last flow that was moved
				memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
				memset(&flow_actions[iLastFlow-1], 0, sizeof(struct flow_tbl_actions));
				iLastFlow --;
				return;
			}
		}
	}
	return;
}

/*
*	Matches packet headers against the installed flows.
*	Returns the flow number if it matches.
*
*	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
*	@param port - The port that the packet was received on.
*	
*/
int flowmatch(uint8_t *pBuffer, int port)
{
	int matched_flow = -1;
	int i;
	
	uint8_t eth_src[6];
	uint8_t eth_dst[6];
	uint16_t eth_prot;
	uint16_t vlanid;
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t ip_prot;
	uint16_t tcp_src;
	uint16_t tcp_dst;
	bool port_match, eth_src_match, eth_dst_match, eth_prot_match;
	bool ip_src_match, ip_dst_match, ip_prot_match;
	bool tcp_src_match, tcp_dst_match;
	bool vlan_match;
	bool vtag = false;
	
	memcpy(&eth_dst, pBuffer, 6);
	memcpy(&eth_src, pBuffer + 6, 6);
	memcpy(&eth_prot, pBuffer + 12, 2);

	if (eth_src[0] == 0x21 && eth_src[1] == 0x21)
	{
		//printf("0x21 error\r\n");
		return -2;
	}

	// VLAN tagged
	if (ntohs(eth_prot) == 0x8100)
	{
		memcpy(&vlanid, pBuffer + 14, 2);
		memcpy(&eth_prot, pBuffer + 16, 2);	// Add 4 bytes to the offset
		vtag = true;
	}
	// IP packets
	if (ntohs(eth_prot) == 0x0800)
	{
		if (vtag == true)	// Add 4 bytes to the offset
		{
			memcpy(&ip_src, pBuffer + 30, 4);
			memcpy(&ip_dst, pBuffer + 34, 4);
			memcpy(&ip_prot, pBuffer + 27, 1);
		} else {
			memcpy(&ip_src, pBuffer + 26, 4);
			memcpy(&ip_dst, pBuffer + 30, 4);
			memcpy(&ip_prot, pBuffer + 23, 1);
		}
		// TCP / UDP
		if (ip_prot == 6 || ip_prot == 17)
		{
			if (vtag == true)	// Add 4 bytes to the offset
			{
				memcpy(&tcp_src, pBuffer + 38, 2);
				memcpy(&tcp_dst, pBuffer + 40, 2);
			} else {
				memcpy(&tcp_src, pBuffer + 34, 2);
				memcpy(&tcp_dst, pBuffer + 36, 2);
			}
		}
	}

	for (i=0;i<iLastFlow;i++)
	{
		// Make sure its an active flow
		if (flow_counters[i].active == false)
		{
			continue;
		}
		
		port_match = (ntohl(flow_match[i].match.wildcards) & OFPFW_IN_PORT) || ntohs(flow_match[i].match.in_port) == port;
		eth_src_match = (ntohl(flow_match[i].match.wildcards) & OFPFW_DL_SRC) || memcmp(eth_src, flow_match[i].match.dl_src, 6) == 0;
		eth_dst_match = (ntohl(flow_match[i].match.wildcards) & OFPFW_DL_DST) || memcmp(eth_dst, flow_match[i].match.dl_dst, 6) == 0;
		eth_prot_match = (ntohl(flow_match[i].match.wildcards) & OFPFW_DL_TYPE) || eth_prot == flow_match[i].match.dl_type;
		vlan_match = (ntohl(flow_match[i].match.wildcards) & OFPFW_DL_VLAN) || (vtag == true &&
			(ntohl(vlanid) & VLAN_VID_MASK) == (ntohl(flow_match[i].match.dl_vlan) & VLAN_VID_MASK));

		uint8_t ip_src_wild = ntohl(flow_match[i].match.wildcards) >> 8; // OFPFW_NW_SRC_SHIFT
		ip_src_wild &= 63; // OFPFW_NW_SRC_BITS
		ip_src_match = (ip_src_wild >= 32) || (ntohs(eth_prot) == 0x0800 &&
			(ntohl(ip_src) >> ip_src_wild) == (ntohl(flow_match[i].match.nw_src) >> ip_src_wild));
		
		uint8_t ip_dst_wild = ntohl(flow_match[i].match.wildcards) >> 14;
		ip_dst_wild &= 63;
		ip_dst_match = (ip_dst_wild >= 32) || (ntohs(eth_prot) == 0x0800 &&
			(ntohl(ip_dst) >> ip_dst_wild) == (ntohl(flow_match[i].match.nw_dst) >> ip_dst_wild));

		ip_prot_match = (ntohl(flow_match[i].match.wildcards) & OFPFW_NW_PROTO) || (ntohs(eth_prot) == 0x0800 &&
			ip_prot == flow_match[i].match.nw_proto);
		tcp_src_match = (ntohl(flow_match[i].match.wildcards) & OFPFW_TP_SRC) || (ntohs(eth_prot) == 0x0800 && (ip_prot == 6 || ip_prot == 17) &&
			tcp_src == flow_match[i].match.tp_src);
		tcp_dst_match = (ntohl(flow_match[i].match.wildcards) & OFPFW_TP_DST) || (ntohs(eth_prot) == 0x0800 && (ip_prot == 6 || ip_prot == 17) &&
			tcp_dst == flow_match[i].match.tp_dst);
		
		if (port_match && eth_src_match && eth_dst_match && eth_prot_match && ip_src_match && ip_dst_match && ip_prot_match && tcp_src_match && tcp_dst_match && vlan_match)
		{
			if (matched_flow > -1)
			{
				if(ntohs(flow_match[i].priority) > ntohs(flow_match[matched_flow].priority)) matched_flow = i;
			} else {
				matched_flow = i;
			}
		}
	}

	return matched_flow;
}

/*
*	Compares 2 match fields
*	Return 1 if they are a match
*
*	@param *match_a - pointer to the first match field
*	@param *match_b - pointer to the second match field
*	
*/
int field_match(struct ofp_match *match_a, struct ofp_match *match_b)
{
	int match = 0;

	if (match_a->wildcards == 0xff203800) return 1;	//First check if all wildcards are set, if so return a match

	uint8_t ip_src_wild = ntohl(match_a->wildcards) >> 8;
	ip_src_wild &= 63;
	uint8_t ip_dst_wild = ntohl(match_a->wildcards) >> 14;
	ip_dst_wild &= 63;
	
	// Check all the match fields. There a definitely a more elegant way of doing this and it's on my TODO list to find it!
	match += (((ntohl(match_a->nw_dst) >> ip_dst_wild) == (ntohl(match_b->nw_dst) >> ip_dst_wild)) || ip_dst_wild == 32);
	match += (((ntohl(match_a->nw_src) >> ip_src_wild) == (ntohl(match_b->nw_src) >> ip_src_wild)) || ip_src_wild == 32);
	match += (match_a->dl_vlan == match_b->dl_vlan || (ntohl(match_a->wildcards) & OFPFW_DL_VLAN));
	match += (match_a->in_port == match_b->in_port || (ntohl(match_a->wildcards) & OFPFW_IN_PORT));
	match += (memcmp(match_a->dl_src, match_b->dl_src, 6) == 0 || (ntohl(match_a->wildcards) & OFPFW_DL_SRC));
	match += (memcmp(match_a->dl_dst, match_b->dl_dst, 6) == 0 || (ntohl(match_a->wildcards) & OFPFW_DL_DST));
	match += (match_a->dl_type == match_b->dl_type || (ntohl(match_a->wildcards) & OFPFW_DL_TYPE));
	match += (match_a->nw_proto == match_b->nw_proto || (ntohl(match_a->wildcards) & OFPFW_NW_PROTO));
	match += (match_a->tp_src == match_b->tp_src || (ntohl(match_a->wildcards) & OFPFW_TP_SRC));
	match += (match_a->tp_dst == match_b->tp_dst || (ntohl(match_a->wildcards) & OFPFW_TP_DST));

	if (match == 10 ) return 1; // If all 10 values match or are wild then return 1
	return 0;
}

/*
*	Clears the flow table
*	
*/
void clear_flows(void)
{
	iLastFlow = 0;
	for(int q=0;q<MAX_FLOWS;q++)
	{
		memset(&flow_counters[q], 0, sizeof(struct flows_counter));
		memset(&flow_actions[q], 0, sizeof(struct flow_tbl_actions));
	}
	table_counters.lookup_count = 0;
	table_counters.matched_count = 0;

}

/*
*	Builds the body of a flow stats request
*
*	@param *buffer- pointer to the buffer to store the response
*	@param *first - first flow to include
*	@param *last - last flow to include
*	
*/
int flow_stats_msg(char *buffer, int first, int last)
{
	struct ofp_flow_stats flow_stats;
	struct ofp_action_header *action_hdr1;
	struct ofp_action_header *action_hdr2;
	struct ofp_action_header *action_hdr3;
	struct ofp_action_header *action_hdr4;
	int len = sizeof(struct ofp10_stats_reply);
	int stats_size = 0;
	int actionsize = 0;
	
	for(int k=first; k<last;k++)
	{
		action_hdr1 = flow_actions[k].action1;
		action_hdr2 = flow_actions[k].action2;
		action_hdr3 = flow_actions[k].action3;
		action_hdr4 = flow_actions[k].action4;
		stats_size = sizeof(flow_stats);
		flow_stats.table_id = 0;
		memcpy(&flow_stats.match, &flow_match[k].match, sizeof(struct ofp_match));
		memcpy(&flow_stats.cookie, &flow_match[k].cookie, sizeof(uint64_t));
		memcpy(&flow_stats.priority, &flow_match[k].priority, sizeof(uint16_t));
		memcpy(&flow_stats.idle_timeout, &flow_match[k].idle_timeout, sizeof(uint16_t));
		memcpy(&flow_stats.hard_timeout, &flow_match[k].hard_timeout, sizeof(uint16_t));
		flow_stats.duration_sec = HTONL(totaltime - flow_counters[k].duration);
		flow_stats.duration_nsec = 0;
		flow_stats.packet_count = htonll(flow_counters[k].hitCount);
		flow_stats.byte_count = htonll(flow_counters[k].bytes);
		actionsize = ntohs(action_hdr1->len) + ntohs(action_hdr2->len) + ntohs(action_hdr3->len) + ntohs(action_hdr4->len);
		flow_stats.length = htons(stats_size + actionsize);
		
		memcpy(buffer + len, &flow_stats, stats_size);
		len += stats_size;
		
		if(ntohs(action_hdr1->len) > 0)
		{
			memcpy(buffer + len, &flow_actions[k].action1, ntohs(action_hdr1->len));
			stats_size += ntohs(action_hdr1->len);
			len += ntohs(action_hdr1->len);
		}
		
		if(ntohs(action_hdr2->len) > 0)
		{
			memcpy(buffer + len, &flow_actions[k].action2, ntohs(action_hdr2->len));
			stats_size += ntohs(action_hdr2->len);
			len += ntohs(action_hdr2->len);
		}
		
		if(ntohs(action_hdr3->len) > 0)
		{
			memcpy(buffer + len, &flow_actions[k].action3, ntohs(action_hdr3->len));
			stats_size += ntohs(action_hdr3->len);
			len += ntohs(action_hdr3->len);
		}
		
		if(ntohs(action_hdr4->len) > 0)
		{
			memcpy(buffer + len, &flow_actions[k].action4, ntohs(action_hdr4->len));
			stats_size += ntohs(action_hdr4->len);
			len += ntohs(action_hdr4->len);
		}
	}
	return len;
}
