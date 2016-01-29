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
#include "ipv4/lwip/ip.h"
#include "ipv4/lwip/inet_chksum.h"
#include "ipv4/lwip/ip_addr.h"
#include "lwip/tcp_impl.h"
#include "lwip/udp.h"
#include "switch.h"

// Global variables
extern int iLastFlow;
extern int OF_Version;
extern struct ofp_flow_mod flow_match[MAX_FLOWS];
extern struct ofp13_flow_mod flow_match13[MAX_FLOWS];
extern uint8_t *ofp13_oxm_match[MAX_FLOWS];
extern uint8_t *ofp13_oxm_inst[MAX_FLOWS];
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
*	Updates the IP Checksum after a SET FIELD operation.
*	Returns the flow number if it matches.
*
*	@param *p_uc_data - Pointer to the buffer that contains the packet to be updated.
*	@param packet_size - The size of the packet.
*	@param iphdr_offset - IP Header offset.
*	
*/
void set_ip_checksum(uint8_t *p_uc_data, int packet_size, int iphdr_offset)
{
	struct ip_hdr *iphdr;
	struct tcp_hdr *tcphdr;
	struct udp_hdr *udphdr;
	int payload_offset;
	
	iphdr = p_uc_data + iphdr_offset;
	payload_offset = iphdr_offset + IPH_HL(iphdr)*4;
	struct pbuf *p = pbuf_alloc(PBUF_RAW, packet_size - payload_offset, PBUF_ROM);
	p->payload = p_uc_data + payload_offset;
	if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
		tcphdr = (struct tcp_hdr*)(p_uc_data + payload_offset);
		tcphdr->chksum = 0;
		tcphdr->chksum = inet_chksum_pseudo(p,
		(ip_addr_t*)&(iphdr->src),
		(ip_addr_t*)&(iphdr->dest),
		IP_PROTO_TCP,
		packet_size - payload_offset);
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
		udphdr = (struct udp_hdr*)(p_uc_data + payload_offset);
		udphdr->chksum = 0;
		udphdr->chksum = inet_chksum_pseudo(p,
		(ip_addr_t*)&(iphdr->src),
		(ip_addr_t*)&(iphdr->dest),
		IP_PROTO_UDP,
		packet_size - payload_offset);
	}
	pbuf_free(p);
	
	IPH_CHKSUM_SET(iphdr, 0);
	IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IPH_HL(iphdr)*4));
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
			if (OF_Version == 1)
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
			} else if (OF_Version == 4)
			{
				if (flow_match13[i].idle_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && (totaltime - flow_counters[i].lastmatch) >= ntohs(flow_match13[i].idle_timeout))
				{
					if (flow_match13[i].flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(i,OFPRR_IDLE_TIMEOUT);
					// Clear flow counters
					memset(&flow_counters[i], 0, sizeof(struct flows_counter));
					// Copy the last flow to here to fill the gap
					memcpy(&flow_match13[i], &flow_match13[iLastFlow-1], sizeof(struct ofp13_flow_mod));					
					// If there are OXM match fields move them too
					ofp13_oxm_match[i] = ofp13_oxm_match[iLastFlow-1];
					ofp13_oxm_match[iLastFlow-1] = NULL;
					memcpy(&flow_counters[i], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
					// Clear the counters from the last flow that was moved
					memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
					iLastFlow --;
					return;
				}
			
				if (flow_match13[i].hard_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && (totaltime - flow_counters[i].duration) >= ntohs(flow_match13[i].hard_timeout))
				{
					if (flow_match13[i].flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(i,OFPRR_HARD_TIMEOUT);
					// Clear flow counters
					memset(&flow_counters[i], 0, sizeof(struct flows_counter));
					// Copy the last flow to here to fill the gap
					memcpy(&flow_match13[i], &flow_match13[iLastFlow-1], sizeof(struct ofp13_flow_mod));
					// If there are OXM match fields move them too
					ofp13_oxm_match[i] = ofp13_oxm_match[iLastFlow-1];
					ofp13_oxm_match[iLastFlow-1] = NULL;
					memcpy(&flow_counters[i], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
					// Clear the counters from the last flow that was moved
					memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
					iLastFlow --;
					return;
				}
			}
		}
	}
	return;
}

/*
*	Matches packet headers against the installed flows for OpenFlow v1.0 (0x01).
*	Returns the flow number if it matches.
*
*	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
*	@param port - The port that the packet was received on.
*	
*/
int flowmatch10(uint8_t *pBuffer, int port)
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
*	Matches packet headers against the installed flows for OpenFlow v1.3 (0x04).
*	Returns the flow number if it matches.
*
*	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
*	@param port - The port that the packet was received on.
*	
*/
int flowmatch13(uint8_t *pBuffer, int port)
{
	int matched_flow = -1;
	int priority_match = -1;
	uint8_t eth_src[6];
	uint8_t eth_dst[6];
	uint16_t eth_prot;
	uint16_t vlanid = 0;
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t ip_prot;
	uint16_t tcp_src;
	uint16_t tcp_dst;
	bool vtag = false;
	int match_size;
	struct oxm_header13 oxm_header;
	uint8_t oxm_value8;
	uint16_t oxm_value16;
	uint32_t oxm_value32;
	uint8_t oxm_eth[6];
	uint8_t oxm_ipv4[4];
	uint16_t oxm_ipv6[8];
						
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
	
	for (int i=0;i<iLastFlow;i++)
	{
		// Make sure its an active flow
		if (flow_counters[i].active == false)
		{
			continue;
		}		
		// If the flow has no match fields (full wild) it is an automatic match	
		if (ofp13_oxm_match[i] ==  NULL)
		{
			if ((ntohs(flow_match13[i].priority) > ntohs(flow_match13[matched_flow].priority)) || matched_flow == -1) matched_flow = i;
			continue;
		}
		// If this flow is of a lower priority then one that is already match then there is no point going through a check.
		if (matched_flow > -1 && (ntohs(flow_match13[matched_flow].priority) > ntohs(flow_match13[i].priority))) continue;
		
		// Main flow match loop			
		match_size = 0;				
		while (match_size < (ntohs(flow_match13[i].match.length)-4))
		{
			memcpy(&oxm_header, ofp13_oxm_match[i] + match_size,4);
			oxm_header.oxm_field = oxm_header.oxm_field >> 1;
			switch(oxm_header.oxm_field)
			{
				case OFPXMT_OFB_IN_PORT:
				memcpy(&oxm_value32, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 4);
				if ( port == ntohl(oxm_value32))
				{
					priority_match = i;
				} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;

				case OFPXMT_OFB_ETH_DST:
				memcpy(&oxm_eth, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 6);
				if (memcmp(eth_dst, oxm_eth, 6) == 0)
				{
					priority_match = i;
				} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;
				
				case OFPXMT_OFB_ETH_SRC:
				memcpy(&oxm_eth, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 6);
				if (memcmp(eth_dst, oxm_eth, 6) == 0)
				{
					priority_match = i;
				} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;

				case OFPXMT_OFB_ETH_TYPE:
				memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
				if (eth_prot == oxm_value16)
				{
					priority_match = i;
				} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}			
				break;
				
				case OFPXMT_OFB_IP_PROTO:
				memcpy(&oxm_value8, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 1);
				if (ip_prot == oxm_value8)
				{
					priority_match = i;
				} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}			
				break;

				case OFPXMT_OFB_IPV4_SRC:
				memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 4);
				if (memcmp(ip_src, oxm_eth, 4) == 0)
				{
					priority_match = i;
					} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;
				
				case OFPXMT_OFB_IPV4_DST:
				memcpy(&oxm_ipv4, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 4);
				if (memcmp(ip_dst, oxm_eth, 4) == 0)
				{
					priority_match = i;
					} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;

// 				case OFPXMT_OFB_IPV6_SRC:
// 				memcpy(&oxm_ipv6, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 16);
// 				if (memcmp(ip_src, oxm_eth, 16) == 0)
// 				{
// 					priority_match = i;
// 					} else {
// 					priority_match = -1;
// 					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
// 					continue;
// 				}
// 				break;
// 				
// 				case OFPXMT_OFB_IPV6_DST:
// 				memcpy(&oxm_ipv6, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 16);
// 				if (memcmp(ip_dst, oxm_eth, 16) == 0)
// 				{
// 					priority_match = i;
// 					} else {
// 					priority_match = -1;
// 					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
// 					continue;
// 				}
// 				break;

				case OFPXMT_OFB_TCP_SRC:
				memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
				if (tcp_src == oxm_value16)
				{
					priority_match = i;
					} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;

				case OFPXMT_OFB_TCP_DST:
				memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
				if (tcp_dst == oxm_value16)
				{
					priority_match = i;
					} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;

				case OFPXMT_OFB_UDP_SRC:
				memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
				if (tcp_src == oxm_value16)
				{
					priority_match = i;
					} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;

				case OFPXMT_OFB_UDP_DST:
				memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
				if (tcp_dst == oxm_value16)
				{
					priority_match = i;
					} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;
										
	 			case OFPXMT_OFB_VLAN_VID:
	 			memcpy(&oxm_value16, ofp13_oxm_match[i] + sizeof(struct oxm_header13) + match_size, 2);
				oxm_value16 -= 0x10;
				if (vtag == true && vlanid == oxm_value16)
				{
					priority_match = i;
				} else {
					priority_match = -1;
					match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
					continue;
				}
				break;			
			};
			matched_flow = priority_match;
			match_size += (oxm_header.oxm_len + sizeof(struct oxm_header13));
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
int field_match10(struct ofp_match *match_a, struct ofp_match *match_b)
{
	int match = 0;

	if (match_a->wildcards == 0xff203800) return 1;	//First check if all wildcards are set, if so return a match

	uint8_t ip_src_wild = ntohl(match_a->wildcards) >> 8;
	ip_src_wild &= 63;
	uint8_t ip_dst_wild = ntohl(match_a->wildcards) >> 14;
	ip_dst_wild &= 63;
	
	// Check all the match fields. There is definitely a more elegant way of doing this and it's on my TODO list!
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
*	Builds the body of a flow stats request for OF 1.0
*
*	@param *buffer- pointer to the buffer to store the response
*	@param *first - first flow to include
*	@param *last - last flow to include
*	
*/
int flow_stats_msg10(char *buffer, int first, int last)
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

/*
*	Builds the body of a flow stats request for OF 1.3
*
*	@param *buffer- pointer to the buffer to store the response
*	@param *first - first flow to include
*	@param *last - last flow to include
*
*/
int flow_stats_msg13(char *buffer, int first, int last)
{
	struct ofp13_flow_stats flow_stats;
	int stats_size = 0;
	char *buffer_ptr = buffer;
	int inst_size;
	int stats_len;
	int len;
	int pad = 0;	
	
	for(int k = first; k<last;k++)
	{
		stats_size = sizeof(flow_stats);
		flow_stats.table_id = 100;
		memcpy(&flow_stats.cookie, &flow_match13[k].cookie, sizeof(uint64_t));
		memcpy(&flow_stats.priority, &flow_match13[k].priority, sizeof(uint16_t));
		memcpy(&flow_stats.idle_timeout, &flow_match13[k].idle_timeout, sizeof(uint16_t));
		memcpy(&flow_stats.hard_timeout, &flow_match13[k].hard_timeout, sizeof(uint16_t));
		memcpy(&flow_stats.match, &flow_match13[k].match, sizeof(struct ofp13_match));
		flow_stats.duration_sec = htonl(totaltime - flow_counters[k].duration);				
		flow_stats.duration_nsec = 0;
		flow_stats.packet_count = htonll(flow_counters[k].hitCount);
		flow_stats.byte_count = htonll(flow_counters[k].bytes);
		flow_stats.flags = 0;
		
		if (htons(flow_match13[k].match.length) > 4)
		{		
			len = stats_size + (htons(flow_match13[k].match.length)-8);
			if (len % 8 != 0)
			{				
				pad = (8-(len % 8));
				len += pad;
			}
			stats_len = len;
			memcpy(buffer_ptr + (stats_size - 4), ofp13_oxm_match[k], htons(flow_match13[k].match.length)-4);
			memset(buffer_ptr + (len-pad), 0, pad);		//Pad the match fields with zero to a multiple of 8
		} else {
			stats_len = stats_size;
		}
		buffer_ptr += stats_len;
		if (ofp13_oxm_inst[k] != NULL)
		{
			if (htons(flow_match13[k].match.length) > 4)
			{
				inst_size = ntohs(flow_match13[k].header.length) - len;
			} else {
				inst_size = ntohs(flow_match13[k].header.length) - (stats_size + (htons(flow_match13[k].match.length)-4));
			}
			memcpy(buffer_ptr, ofp13_oxm_inst[k], inst_size);
			stats_len += inst_size;		
			buffer_ptr += inst_size;
		}
		flow_stats.length = htons(stats_len);
		memcpy(buffer_ptr - stats_len, &flow_stats, stats_size);
	}
	return (buffer_ptr - buffer);
	
}