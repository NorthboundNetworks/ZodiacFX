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
#include "trace.h"
#include "config_zodiac.h"
#include "openflow.h"
#include "of_helper.h"
#include "command.h"
#include "lwip/tcp.h"
#include "ipv4/lwip/ip.h"
#include "ipv4/lwip/inet_chksum.h"
#include "ipv4/lwip/ip_addr.h"
#include "lwip/tcp_impl.h"
#include "lwip/udp.h"
#include "switch.h"
#include "timers.h"

#define ALIGN8(x) (x+7)/8*8

// Global variables
extern struct zodiac_config Zodiac_Config;
extern int iLastFlow;
extern int iLastMeter;
extern int OF_Version;
extern int totaltime;
extern uint8_t last_port_status[TOTAL_PORTS];
extern uint8_t port_status[TOTAL_PORTS];
extern struct flows_counter flow_counters[MAX_FLOWS_13];
extern struct table_counter table_counters[MAX_TABLES];
extern struct meter_entry13 *meter_entry[MAX_METER_13];
extern struct meter_band_stats_array band_stats_array[MAX_METER_13];
extern struct group_entry13 group_entry13[MAX_GROUPS];
extern struct action_bucket action_bucket[MAX_BUCKETS];
extern struct ofp_flow_mod *flow_match10[MAX_FLOWS_10];
extern struct flow_tbl_actions *flow_actions10[MAX_FLOWS_10];
extern struct ofp13_flow_mod *flow_match13[MAX_FLOWS_13];
extern uint8_t *ofp13_oxm_match[MAX_FLOWS_13];
extern uint8_t *ofp13_oxm_inst[MAX_FLOWS_13];
extern uint16_t ofp13_oxm_inst_size[MAX_FLOWS_13];

// Local Variables
uint8_t timer_alt = 0;
uint8_t update_interval = 0;
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
	struct icmp_echo_hdr *icmphdr;
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
		TRACE("of_helper.c: TCP header modified, recalculating Checksum. 0x%X", htons(tcphdr->chksum));
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
		udphdr = (struct udp_hdr*)(p_uc_data + payload_offset);
		udphdr->chksum = 0;
		udphdr->chksum = inet_chksum_pseudo(p,
		(ip_addr_t*)&(iphdr->src),
		(ip_addr_t*)&(iphdr->dest),
		IP_PROTO_UDP,
		packet_size - payload_offset);
		TRACE("of_helper.c: UDP header modified, recalculating Checksum. 0x%X", htons(udphdr->chksum));
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {
		icmphdr = (struct icmp_echo_hdr*)(p_uc_data + payload_offset);
		icmphdr->chksum = 0;
		icmphdr->chksum = inet_chksum(icmphdr, packet_size - payload_offset);
		TRACE("of_helper.c: ICMP header modified, recalculating Checksum. 0x%X", htons(icmphdr->chksum));
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
	totaltime ++; // Because this is called every 500ms totaltime is actually 2 x the real time
	// Round robin the timer events so they don't have such a big impact on switching
	update_interval ++;
	if ((update_interval/2) > Zodiac_Config.stats_interval)
	{
		if (timer_alt == 0){
			if (Zodiac_Config.stats_interval > 0) update_port_stats();
			timer_alt = 1;
		} else if (timer_alt == 1){
			flow_timeouts();
			if (Zodiac_Config.stats_interval > 0) update_port_status();
			// If port status has changed send a port status message
			for (int x=0;x<TOTAL_PORTS;x++)
			{
				if (last_port_status[x] != port_status[x] && OF_Version == 1 && Zodiac_Config.of_port[x] == 1) port_status_message10(x);
				if (last_port_status[x] != port_status[x] && OF_Version == 4 && Zodiac_Config.of_port[x] == 1) port_status_message13(x);
			}
			timer_alt = 0;
		}
		update_interval = 2;
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
int flowmatch10(uint8_t *pBuffer, int port, struct packet_fields *fields)
{
	int matched_flow = -1;
	int i;
	uint8_t *eth_dst = pBuffer;
	uint8_t *eth_src = pBuffer + 6;
	uint8_t icmp_type;
	uint8_t icmp_code;
	bool port_match, eth_src_match, eth_dst_match, eth_prot_match;
	bool ip_src_match, ip_dst_match, ip_prot_match;
	bool tcp_src_match = false;
	bool tcp_dst_match = false;
	bool vlan_match;
	uint64_t zero_field = 0;

	if (!fields->parsed) {
		packet_fields_parser(pBuffer, fields);
	}

	TRACE("of_helper.c: Looking for match from port %d : "
	"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X eth type %4.4X", port,
	eth_src[0], eth_src[1], eth_src[2], eth_src[3], eth_src[4], eth_src[5],
	eth_dst[0], eth_dst[1], eth_dst[2], eth_dst[3], eth_dst[4], eth_dst[5],
	ntohs(fields->eth_prot))

	// IP packets
	if (ntohs(fields->eth_prot) == 0x0800 && fields->ip_prot == 1)		// ICMP
	{
		if (fields->isVlanTag == true)	// Add 4 bytes to the offset
		{
			memcpy(&icmp_type, pBuffer + 38, 1);
			memcpy(&icmp_code, pBuffer + 49, 1);
		} else {
			memcpy(&icmp_type, pBuffer + 34, 1);
			memcpy(&icmp_code, pBuffer + 35, 1);
		}
	}

	for (i=0;i<iLastFlow;i++)
	{
		// Make sure its an active flow
		if (flow_counters[i].active == false)
		{
			continue;
		}

		// If this flow is of a lower priority then one that is already match then there is no point going through a check.
		if (matched_flow > -1)
		{
			if(ntohs(flow_match10[i]->priority) <= ntohs(flow_match10[matched_flow]->priority)) continue;
		}

		port_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_IN_PORT) || ntohs(flow_match10[i]->match.in_port) == port || flow_match10[i]->match.in_port == 0;
		eth_src_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_DL_SRC) || memcmp(eth_src, flow_match10[i]->match.dl_src, 6) == 0 || memcmp(flow_match10[i]->match.dl_src, zero_field, 6) == 0;
		eth_dst_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_DL_DST) || memcmp(eth_dst, flow_match10[i]->match.dl_dst, 6) == 0 || memcmp(flow_match10[i]->match.dl_dst, zero_field, 6) == 0;
		eth_prot_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_DL_TYPE) || fields->eth_prot == flow_match10[i]->match.dl_type || flow_match10[i]->match.dl_type == 0;
		vlan_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_DL_VLAN) || (fields->isVlanTag == true && (ntohl(fields->vlanid) & VLAN_VID_MASK) == (ntohl(flow_match10[i]->match.dl_vlan) & VLAN_VID_MASK)) || (ntohs(flow_match10[i]->match.dl_vlan) == OFP_VLAN_NONE);

		uint8_t ip_src_wild = ntohl(flow_match10[i]->match.wildcards) >> 8; // OFPFW_NW_SRC_SHIFT
		ip_src_wild &= 63; // OFPFW_NW_SRC_BITS
		ip_src_match = (ip_src_wild >= 32) || (ntohs(fields->eth_prot) == 0x0800 && (ntohl(fields->ip_src) >> ip_src_wild) == (ntohl(flow_match10[i]->match.nw_src) >> ip_src_wild)) || flow_match10[i]->match.nw_src == 0;

		uint8_t ip_dst_wild = ntohl(flow_match10[i]->match.wildcards) >> 14;
		ip_dst_wild &= 63;
		ip_dst_match = (ip_dst_wild >= 32) || (ntohs(fields->eth_prot) == 0x0800 && (ntohl(fields->ip_dst) >> ip_dst_wild) == (ntohl(flow_match10[i]->match.nw_dst) >> ip_dst_wild)) || flow_match10[i]->match.nw_dst == 0;
		ip_prot_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_NW_PROTO) || (ntohs(fields->eth_prot) == 0x0800 && fields->ip_prot == flow_match10[i]->match.nw_proto) || flow_match10[i]->match.nw_proto == 0  || ntohs(fields->eth_prot) != 0x0800;
		// If it is TCP or UDP we match on source and destination ports
		if (ntohs(fields->eth_prot) == 0x0800 && (fields->ip_prot == 6 || fields->ip_prot == 17))
		{
			tcp_src_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_TP_SRC) || fields->tp_src == flow_match10[i]->match.tp_src || flow_match10[i]->match.tp_src == 0;
			tcp_dst_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_TP_DST) || fields->tp_dst == flow_match10[i]->match.tp_dst || flow_match10[i]->match.tp_dst == 0;
		}
		// If it is ICMP the TCP source and destination ports become type and code values
		if (ntohs(fields->eth_prot) == 0x0800 && fields->ip_prot == 1)
		{
			tcp_src_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_TP_SRC) || icmp_type == ntohs(flow_match10[i]->match.tp_src) || flow_match10[i]->match.tp_src == 0;
			tcp_dst_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_TP_DST) || icmp_code == ntohs(flow_match10[i]->match.tp_dst) || flow_match10[i]->match.tp_dst == 0;
		}
		// If it is ARP then we skip IP and TCP/UDP values
		if (ntohs(fields->eth_prot) == 0x0806)
		{
			ip_src_match = true;
			ip_dst_match = true;
			tcp_src_match = true;
			tcp_dst_match = true;
		}
		if (port_match && eth_src_match && eth_dst_match && eth_prot_match && ip_src_match && ip_dst_match && ip_prot_match && tcp_src_match && tcp_dst_match && vlan_match)
		{
			if (matched_flow > -1)
			{
				if(ntohs(flow_match10[i]->priority) > ntohs(flow_match10[matched_flow]->priority)) matched_flow = i;
			}
			else
			{
				matched_flow = i;
			}
		}
	}

	return matched_flow;
}

/*
*	Populate the packet header fields.
*
*	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
*	@param *fields - pointer the struct to store the field values.
*
*/
void packet_fields_parser(uint8_t *pBuffer, struct packet_fields *fields) {
	// VLAN EtherTypes
	static const uint8_t vlan1[2] = { 0x81, 0x00 };
	static const uint8_t vlan2[2] = { 0x88, 0xa8 };
	static const uint8_t vlan3[2] = { 0x91, 0x00 };
	static const uint8_t vlan4[2] = { 0x92, 0x00 };
	static const uint8_t vlan5[2] = { 0x93, 0x00 };
	// MPLS EtherTypes
	static const uint8_t mpls1[2] = { 0x88, 0x47 };
	static const uint8_t mpls2[2] = { 0x88, 0x48 };

	fields->isVlanTag = false;
	fields->isMPLSTag = false;
	uint8_t *eth_type = pBuffer + 12;
	
	// Get MPLS values
	if (memcmp(eth_type, mpls1, 2)==0 || memcmp(eth_type, mpls2, 2)==0)
	{
		uint32_t mpls;
		memcpy(&mpls, eth_type+2, 4);
		fields->mpls_label = ntohl(mpls)>>12;
		fields->mpls_tc = (ntohl(mpls)>>9)&7;
		fields->mpls_bos = (ntohl(mpls)>>8)&1;
		fields->isMPLSTag = true;
		eth_type += 4;
	}
	// Get VLAN IDs
	while(memcmp(eth_type, vlan1, 2)==0 || memcmp(eth_type, vlan2, 2)==0 || memcmp(eth_type, vlan3, 2)==0 || memcmp(eth_type, vlan4, 2)==0 || memcmp(eth_type, vlan5, 2)==0)
	{
		if(fields->isVlanTag == false){ // save outermost value
			uint8_t tci[2] = { eth_type[2]&0x0f, eth_type[3] };
			memcpy(&fields->vlanid, tci, 2);
		}
		fields->isVlanTag = true;
		eth_type += 4;
	}
	
	memcpy(&fields->eth_prot, eth_type, 2);
	fields->payload = eth_type + 2; // payload points to ip_hdr, etc.
	
	if(ntohs(fields->eth_prot) == 0x0800){
		struct ip_hdr *iphdr = (struct ip_hdr*)fields->payload;
		uint8_t *ip_payload = fields->payload + IPH_HL(iphdr) * 4;
		fields->ip_src = iphdr->src.addr;
		fields->ip_dst = iphdr->dest.addr;
		fields->ip_prot = IPH_PROTO(iphdr);
		if(IPH_PROTO(iphdr)==IP_PROTO_TCP){
			struct tcp_hdr *tcphdr = (struct tcp_hdr*)ip_payload;
			fields->tp_src = tcphdr->src;
			fields->tp_dst = tcphdr->dest;
		}
		if(IPH_PROTO(iphdr)==IP_PROTO_UDP){
			struct udp_hdr *udphdr = (struct udp_hdr*)ip_payload;
			fields->tp_src = udphdr->src;
			fields->tp_dst = udphdr->dest;
		}
	}
	
	if(ntohs(fields->eth_prot) == 0x0806){
		memcpy(&fields->arp_op, fields->payload + 6, 2);
		memcpy(&fields->arp_sha, fields->payload + 8, 6);
		memcpy(&fields->arp_spa, fields->payload + 14, 4);
		memcpy(&fields->arp_tha, fields->payload + 18, 6);
		memcpy(&fields->arp_tpa, fields->payload + 24, 4);
	}
	
	fields->parsed = true;
}

/*
*	Matches packet headers against the installed flows for OpenFlow v1.3 (0x04).
*	Returns the flow number if it matches.
*
*	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
*	@param port - The port that the packet was received on.
*
*/
int flowmatch13(uint8_t *pBuffer, int port, uint8_t table_id, struct packet_fields *fields)
{
	int matched_flow = -1;
	uint8_t *eth_dst = pBuffer;
	uint8_t *eth_src = pBuffer + 6;
	uint16_t oxm_value16;
	uint8_t oxm_ipv4[4];

	if (!fields->parsed) {
		packet_fields_parser(pBuffer, fields);
	}

	TRACE("of_helper.c: Looking for match in table %d from port %d : "
		"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X - eth type %4.4X - VLAN ID %d",
		table_id, port,
		eth_src[0], eth_src[1], eth_src[2], eth_src[3], eth_src[4], eth_src[5],
		eth_dst[0], eth_dst[1], eth_dst[2], eth_dst[3], eth_dst[4], eth_dst[5],
		ntohs(fields->eth_prot), ntohs(fields->vlanid))
	
	for (int i=0;i<iLastFlow;i++)
	{
		// Make sure its an active flow
		if (flow_counters[i].active == false) continue;

		// If the flow is not in the requested table then fail
		if (table_id != flow_match13[i]->table_id) continue;

		// If the flow has no match fields (full wild) it is an automatic match
		if (ofp13_oxm_match[i] ==  NULL)
		{
			if (matched_flow == -1 ||
				(ntohs(flow_match13[i]->priority) > ntohs(flow_match13[matched_flow]->priority)))
				matched_flow = i;
			continue;
		}
		// If this flow is of a lower priority then one that is already match then there is no point going through a check.
		if (matched_flow > -1 &&
			(ntohs(flow_match13[matched_flow]->priority) >= ntohs(flow_match13[i]->priority)))
			continue;

		// Main flow match loop
		bool fields_match = true;
		uint8_t *hdr = ofp13_oxm_match[i];
		uint8_t *tail = hdr + ntohs(flow_match13[i]->match.length) - 4;
		while (fields_match && hdr < tail)
		{
			bool loop_match = false;
			uint32_t field = ntohl(*(uint32_t*)(hdr));
			uint8_t *oxm_value = hdr + 4;
			hdr += 4 + OXM_LENGTH(field);

			// Require (+ve) field match to move onto next field
			fields_match = false;
			switch(field)
			{
				case OXM_OF_IN_PORT:
				fields_match = (port == ntohl(*(uint32_t*)oxm_value));
				break;

				case OXM_OF_ETH_DST:
				fields_match = (memcmp(eth_dst, oxm_value, 6) == 0);
				break;

				case OXM_OF_ETH_DST_W:
				loop_match = true;
				for (int j=0; j<6; j++ )
				{
					loop_match &= ((oxm_value[j] & oxm_value[6+j]) ==
									(eth_dst[j] & oxm_value[6+j]));
				}
				fields_match = loop_match;
				break;

				case OXM_OF_ETH_SRC:
				fields_match = (memcmp(eth_src, oxm_value, 6) == 0);
				break;

				case OXM_OF_ETH_SRC_W:
				loop_match = true;
				for (int j=0; j<6; j++ )
				{
					loop_match &= ((oxm_value[j] & oxm_value[6+j]) ==
									(eth_src[j] & oxm_value[6+j]));
				}
				fields_match = loop_match;
				break;

				case OXM_OF_ETH_TYPE:
				fields_match = ((fields->eth_prot == *(uint16_t*)oxm_value) ||
								*(uint16_t*)oxm_value == htons(0x8847) ||
								*(uint16_t*)oxm_value == htons(0x8848) ||
								fields->isMPLSTag);
				break;

				case OXM_OF_IP_DSCP:
				if (fields->eth_prot == htons(0x0800))
				{
					struct ip_hdr *iph = fields->payload;
					fields_match = ((IPH_TOS(iph)>>2) == oxm_value[0]);
				}
				break;

				case OXM_OF_IP_ECN:
				if (fields->eth_prot == htons(0x0800))
				{
					struct ip_hdr *iph = fields->payload;
					fields_match = ((IPH_TOS(iph)&03) == oxm_value[0]);
				}
				break;

				case OXM_OF_IP_PROTO:
				fields_match = (fields->ip_prot == *oxm_value);
				break;

				case OXM_OF_IPV4_SRC:
				fields_match = (memcmp(&fields->ip_src, oxm_value, 4) == 0);
				break;

				case OXM_OF_IPV4_SRC_W:
				memcpy(oxm_ipv4, &fields->ip_src, 4);
				for (int j=0; j<4; j++)
				{
					oxm_ipv4[j] &= oxm_value[4+j];
				}
				fields_match = (memcmp(oxm_ipv4, oxm_value, 4) == 0);
				break;

				case OXM_OF_IPV4_DST:
				fields_match = (memcmp(&fields->ip_dst, oxm_value, 4) == 0);
				break;

				case OXM_OF_IPV4_DST_W:
				memcpy(oxm_ipv4, &fields->ip_dst, 4);
				for (int j=0; j<4; j++ )
				{
					oxm_ipv4[j] &= oxm_value[4+j];
				}
				fields_match = (memcmp(oxm_ipv4, oxm_value, 4) == 0);
				break;

				case OXM_OF_TCP_SRC:
				fields_match = (fields->ip_prot == IP_PROTO_TCP &&
								fields->tp_src == *(uint16_t*)oxm_value);
				break;

				case OXM_OF_TCP_DST:
				fields_match = (fields->ip_prot == IP_PROTO_TCP &&
								fields->tp_dst == *(uint16_t*)oxm_value);
				break;

				case OXM_OF_UDP_SRC:
				fields_match = (fields->ip_prot == IP_PROTO_UDP &&
								fields->tp_src == *(uint16_t*)oxm_value);
				break;

				case OXM_OF_UDP_DST:
				fields_match = (fields->ip_prot == IP_PROTO_UDP &&
								fields->tp_dst == *(uint16_t*)oxm_value);
				break;

				case OXM_OF_VLAN_VID:
				if (fields->isVlanTag)
				{
					oxm_value16 = htons(OFPVID_PRESENT | ntohs(fields->vlanid));
				} else {
					oxm_value16 = htons(OFPVID_NONE);
				}
				fields_match = (oxm_value16 == *(uint16_t*)oxm_value);
				break;

				case OXM_OF_VLAN_VID_W:
				if (fields->isVlanTag)
				{
					oxm_value16 = htons(OFPVID_PRESENT | ntohs(fields->vlanid));
				} else {
					oxm_value16 = htons(OFPVID_NONE);
				}
				oxm_value16 &= *(uint16_t*)(oxm_value+2);
				fields_match = (oxm_value16 == *(uint16_t*)oxm_value);
				break;

				case OXM_OF_VLAN_PCP:
				fields_match = (fields->isVlanTag &&
								(pBuffer[14]>>5) == oxm_value[0]);
				break;

				case OXM_OF_MPLS_LABEL:
				fields_match = (fields->isMPLSTag &&
								ntohl(fields->mpls_label) == *(uint32_t*)oxm_value);
				break;

				case OXM_OF_MPLS_TC:
				fields_match = (fields->isMPLSTag &&
								fields->mpls_tc == *oxm_value);
				break;
				
				case OXM_OF_MPLS_BOS:
				fields_match = (fields->isMPLSTag &&
								fields->mpls_bos == *oxm_value);
				break;

				case OXM_OF_ARP_OP:
				fields_match = (fields->eth_prot == htons(0x0806) &&
								fields->arp_op == *(uint16_t*)oxm_value);
				break;
				
				case OXM_OF_ARP_SPA:
				fields_match = (fields->eth_prot == htons(0x0806) &&
								memcmp(&fields->arp_spa, oxm_value, 4) == 0);
				break;

				case OXM_OF_ARP_SPA_W:
				if (fields->eth_prot == htons(0x0806))
				{
					memcpy(oxm_ipv4, &fields->arp_spa, 4);
					for (int j=0; j<4; j++)
					{
						oxm_ipv4[j] &= oxm_value[4+j];
					}
					fields_match = (memcmp(oxm_ipv4, oxm_value, 4) == 0);
				}
				break;
				
				case OXM_OF_ARP_TPA:
				fields_match = (fields->eth_prot == htons(0x0806) &&
								memcmp(&fields->arp_tpa, oxm_value, 4) == 0);
				break;

				case OXM_OF_ARP_TPA_W:
				if (fields->eth_prot == htons(0x0806))
				{
					memcpy(oxm_ipv4, &fields->arp_tpa, 4);
					for (int j=0; j<4; j++)
					{
						oxm_ipv4[j] &= oxm_value[4+j];
					}
					fields_match = (memcmp(oxm_ipv4, oxm_value, 4) == 0);
				}
				break;
				
				case OXM_OF_ARP_SHA:
				fields_match = (fields->eth_prot == htons(0x0806) &&
								memcmp(&fields->arp_sha, oxm_value, 6) == 0);
				break;

				case OXM_OF_ARP_SHA_W:
				if (fields->eth_prot == htons(0x0806))
				{
					loop_match = true;
					for (int j=0; j<6; j++ )
					{
						loop_match &= ((oxm_value[j] & oxm_value[6+j]) ==
									   (fields->arp_sha[j] & oxm_value[6+j]));
					}
					fields_match = loop_match;
				}
				break;
				
				case OXM_OF_ARP_THA:
				fields_match = (fields->eth_prot == htons(0x0806) &&
								memcmp(&fields->arp_tha, oxm_value, 6) == 0);
				break;

				case OXM_OF_ARP_THA_W:
				if (fields->eth_prot == htons(0x0806))
				{
					loop_match = true;
					for (int j=0; j<6; j++ )
					{
						loop_match &= ((oxm_value[j] & oxm_value[6+j]) ==
									   (fields->arp_tha[j] & oxm_value[6+j]));
					}
					fields_match = loop_match;
				}
				break;
												
				default:
				TRACE("of_helper.c: flow %d: unsupported field (0x%08x) - flow ignored !",
				      i+1, field);
				break;
			}
		}
		if (fields_match)
		{
			matched_flow = i;
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

#define PREREQ_INVALID 1<<0
#define PREREQ_VLAN 1<<1
#define PREREQ_IPV4 1<<2
#define PREREQ_IPV6 1<<3
#define PREREQ_ARP 1<<4
#define PREREQ_TCP 1<<5
#define PREREQ_UDP 1<<6
#define PREREQ_SCTP 1<<7
#define PREREQ_ICMPV4 1<<8
#define PREREQ_ICMPV6 1<<9
#define PREREQ_ND_SLL 1<<10
#define PREREQ_ND_TLL 1<<11
#define PREREQ_MPLS 1<<12
#define PREREQ_PBB 1<<13
#define PREREQ_ETH_TYPE_MASK (PREREQ_IPV4 | PREREQ_IPV6 | PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB)
#define PREREQ_IP_PROTO_MASK (PREREQ_TCP | PREREQ_UDP | PREREQ_SCTP | PREREQ_ICMPV4 | PREREQ_ICMPV6)
#define PREREQ_IP_MASK (PREREQ_IPV4 | PREREQ_IPV6)
#define PREREQ_ND_MASK (PREREQ_ND_SLL | PREREQ_ND_TLL)

static uint32_t match_prereq(uint8_t *oxm, int length)
{
	uint32_t ret = 0;
	uint8_t *hdr = oxm;
	while(hdr < oxm+length){
		uint16_t eth_type;
		uint32_t field = ntohl(*(uint32_t*)(hdr));
		switch(field){
			case OXM_OF_VLAN_PCP:
				ret |= PREREQ_VLAN;
				break;
			case OXM_OF_ETH_TYPE:
				eth_type = ntohl(*(uint16_t*)(hdr+4));
				switch(eth_type){
					case 0x0800:
						if (ret & PREREQ_IP_MASK == PREREQ_IPV6){
							ret |= PREREQ_INVALID;
						}
						ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV4;
						break;
					case 0x86dd:
						if (ret & PREREQ_IP_MASK == PREREQ_IPV4){
							ret |= PREREQ_INVALID;
						}
						ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
						break;
					case 0x0806:
						ret |= PREREQ_ARP;
						break;
					case 0x8847:
					case 0x8848:
						ret |= PREREQ_MPLS;
						break;
					case 0x88e7:
						ret |= PREREQ_PBB;
						break;
				}
				break;
			case OXM_OF_IP_PROTO:
				switch(hdr[4]){
					case 1:
						ret |= PREREQ_ICMPV4;
						break;
					case 6:
						ret |= PREREQ_TCP;
						break;
					case 17:
						ret |= PREREQ_UDP;
						break;
					case 58:
						ret |= PREREQ_ICMPV6;
						break;
					case 132:
						ret |= PREREQ_SCTP;
						break;
				}
				if (ret & PREREQ_IP_MASK == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_ICMPV6_TYPE:
				switch(hdr[4]){
					case 135:
						if (ret & PREREQ_ND_MASK == PREREQ_ND_TLL){
							ret |= PREREQ_INVALID;
						}
						ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_SLL;
						break;
					case 136:
						if (ret & PREREQ_ND_MASK == PREREQ_ND_SLL){
							ret |= PREREQ_INVALID;
						}
						ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_TLL;
						break;
				}
				ret |= PREREQ_ICMPV6;
				if (ret & PREREQ_IP_MASK == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_IP_DSCP:
			case OXM_OF_IP_ECN:
				if (ret & PREREQ_IP_MASK == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_ICMPV4_TYPE:
			case OXM_OF_ICMPV4_CODE:
				ret |= PREREQ_ICMPV4;
			case OXM_OF_IPV4_DST:
			case OXM_OF_IPV4_DST_W:
			case OXM_OF_IPV4_SRC:
			case OXM_OF_IPV4_SRC_W:
				if (ret & PREREQ_IP_MASK == PREREQ_IPV6){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV4;
				break;
			case OXM_OF_TCP_SRC:
			case OXM_OF_TCP_DST:
				ret |= PREREQ_TCP;
				if (ret & PREREQ_IP_MASK == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_UDP_SRC:
			case OXM_OF_UDP_DST:
				ret |= PREREQ_UDP;
				if (ret & PREREQ_IP_MASK == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_SCTP_SRC:
			case OXM_OF_SCTP_DST:
				ret |= PREREQ_SCTP;
				if (ret & PREREQ_IP_MASK == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_ARP_OP:
			case OXM_OF_ARP_SPA:
			case OXM_OF_ARP_SPA_W:
			case OXM_OF_ARP_TPA:
			case OXM_OF_ARP_TPA_W:
			case OXM_OF_ARP_SHA:
			case OXM_OF_ARP_THA:
				ret |= PREREQ_ARP;
				break;
			case OXM_OF_ICMPV6_CODE:
				ret |= PREREQ_ICMPV6;
			case OXM_OF_IPV6_SRC:
			case OXM_OF_IPV6_SRC_W:
			case OXM_OF_IPV6_DST:
			case OXM_OF_IPV6_DST_W:
			case OXM_OF_IPV6_FLABEL:
			case OXM_OF_IPV6_EXTHDR:
			case OXM_OF_IPV6_EXTHDR_W:
				if (ret & PREREQ_IP_MASK == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_IPV6_ND_TARGET:
				if (ret & PREREQ_ND_MASK == 0){
					ret |= PREREQ_ND_MASK;
				}
				ret |= PREREQ_ICMPV6;
				if (ret & PREREQ_IP_MASK == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_IPV6_ND_SLL:
				if (ret & PREREQ_ND_MASK == PREREQ_ND_TLL){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_SLL;
				ret |= PREREQ_ICMPV6;
				if (ret & PREREQ_IP_MASK == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_IPV6_ND_TLL:
				if (ret & PREREQ_ND_MASK == PREREQ_ND_SLL){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_TLL;
				ret |= PREREQ_ICMPV6;
				if (ret & PREREQ_IP_MASK == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_MPLS_LABEL:
			case OXM_OF_MPLS_BOS:
			case OXM_OF_MPLS_TC:
				ret |= PREREQ_MPLS;
				break;
			case OXM_OF_PBB_ISID:
				ret |= PREREQ_PBB;
				break;
		}
		hdr += 4 + OXM_LENGTH(field);
	}
	uint32_t flags = 0;
	flags = ret & PREREQ_ETH_TYPE_MASK;
	if (flags!=0 && flags!=PREREQ_IPV4 && flags!=PREREQ_IPV6 && flags!=PREREQ_IP_MASK && flags!=PREREQ_ARP && flags!=PREREQ_MPLS && flags!=PREREQ_PBB){
		ret |= PREREQ_INVALID;
	}
	flags = ret & PREREQ_IP_PROTO_MASK;
	if (flags!=0 && flags!=PREREQ_TCP && flags!=PREREQ_UDP && flags!=PREREQ_SCTP && flags!=PREREQ_ICMPV4 && flags!=PREREQ_ICMPV6){
		ret |= PREREQ_INVALID;
	}
	return ret;
}

/*
*	Compares 2 match oxms
*	Return 1 if a matches for b (b is wider than a)
*
*	@param *match_a - pointer to the first match field
*	@param *match_b - pointer to the second match field
*
*/
int field_match13(uint8_t *oxm_a, int len_a, uint8_t *oxm_b, int len_b)
{
	if (len_a == 0) {
		return 1;
	}
	uint32_t prereq_a = match_prereq(oxm_a, len_a);
	if (prereq_a & PREREQ_INVALID != 0){
		return 0;
	}
	uint8_t *ahdr = oxm_a;
	while (ahdr < oxm_a + len_a){
		uint32_t afield = ntohl(*(uint32_t*)(ahdr));
		uint8_t *bhdr = oxm_b;
		uint32_t bfield = ntohl(*(uint32_t*)(bhdr));
		while (afield != bfield && bhdr < oxm_b + len_b)
		{
			bhdr += 4 + OXM_LENGTH(bfield);
			bfield = ntohl(*(uint32_t*)(bhdr));
		}
		if (afield != bfield)
		{
			return 0;
		}
		switch(bfield){
			uint16_t eth_type;
			case OXM_OF_ETH_TYPE:
				eth_type = ntohs(*(uint16_t*)(bhdr+4));
				switch (eth_type){
					case 0x0800:
						if (prereq_a & (PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB) != 0){
							return 0;
						}
						if (prereq_a & PREREQ_ETH_TYPE_MASK == PREREQ_IPV6){
							return 0;
						}
						break;
					case 0x86dd:
						if (prereq_a & (PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB) != 0){
							return 0;
						}
						if (prereq_a & PREREQ_ETH_TYPE_MASK == PREREQ_IPV4){
							return 0;
						}
						break;
					case 0x0806:
						if (prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_ARP != 0) {
							return 0;
						}
						break;
					case 0x8847:
					case 0x8848:
						if (prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_MPLS != 0) {
							return 0;
						}
						break;
					case 0x88e7:
						if (prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_PBB != 0) {
							return 0;
						}
						break;
				}
				break;
			case OXM_OF_IP_PROTO:
				switch(bhdr[4]){
					case 1:
						if (prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_ICMPV4 != 0) {
							return 0;
						}
						break;
					case 6:
						if (prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_TCP != 0) {
							return 0;
						}
						break;
					case 17:
						if (prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_UDP != 0){
							return 0;
						}
						break;
					case 58:
						if (prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_ICMPV6 != 0){
							return 0;
						}
						break;
					case 132:
						if (prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_SCTP != 0){
							return 0;
						}
						break;
				}
				break;
			case OXM_OF_ICMPV6_TYPE:
				switch(bhdr[4]){
					case 135:
						if (prereq_a & PREREQ_ND_MASK & ~PREREQ_ND_SLL != 0){
							return 0;
						}
						break;
					case 136:
						if (prereq_a & PREREQ_ND_MASK & ~PREREQ_ND_TLL != 0){
							return 0;
						}
						break;
				}
				break;
		}
		if(OXM_HASMASK(bfield)){
                        int length = OXM_LENGTH(bfield)/2;
                        if(OXM_HASMASK(afield)){
                                for(int i=0; i<length; i++){
                                        if (~ahdr[4+length+i] & bhdr[4+length+i] != 0){
                                                return 0;
                                        }
                                }
                                for(int i=0; i<length; i++){
                                        if (ahdr[4+i] & bhdr[4+length+i] != bhdr[4+i]){
                                                return 0;
                                        }
                                }
			} else if (memcmp(ahdr+4, bhdr+4, OXM_LENGTH(bfield)) != 0){
                                return 0;
                        }
		} else if (memcmp(ahdr+4, bhdr+4, OXM_LENGTH(bfield)) != 0){
			uint32_t test = OXM_LENGTH(bfield);
			return 0;
		}
		ahdr += 4 + OXM_LENGTH(afield);
	}
	uint32_t prereq_b = match_prereq(oxm_b, len_b);
	if (prereq_b & PREREQ_INVALID != 0){
		return 0;
	}
	if (prereq_a & PREREQ_ETH_TYPE_MASK & ~(prereq_b & PREREQ_ETH_TYPE_MASK) != 0){
		return 0;
	}
	if (prereq_a & PREREQ_ND_MASK & ~(prereq_b & PREREQ_ND_MASK) != 0){
		return 0;
	}
	if (prereq_b & PREREQ_VLAN != 0) {
		uint8_t *ahdr = oxm_a;
		while(ahdr < oxm_a + len_a){
			uint32_t afield = *(uint32_t*)(ahdr);
			switch(afield){
				case OXM_OF_VLAN_VID_W:
					if (ntohs(*(uint16_t*)(ahdr+6)) & OFPVID_PRESENT != 0){
						break;
					}
				case OXM_OF_VLAN_VID:
					if (ntohs(*(uint16_t*)(ahdr+4)) == OFPVID_NONE){
						return 0;
					}
					break;
			}
			ahdr += 4 + OXM_LENGTH(afield);
		}
	}
	return 1;
}

/*
*	Remove a flow entry from the flow table (OF 1.3)
*
*	@param flow_id - the idex number of the flow to remove
*
*/
void remove_flow13(int flow_id)
{
	// Free the memory allocated for the match and instructions
	if(ofp13_oxm_match[flow_id] != NULL)
	{
		membag_free(ofp13_oxm_match[flow_id]);
		ofp13_oxm_match[flow_id] = NULL;
	}
	if(ofp13_oxm_inst[flow_id] != NULL)
	{
		membag_free(ofp13_oxm_inst[flow_id]);
		ofp13_oxm_inst[flow_id] = NULL;
	}
	if(flow_match13[flow_id] != NULL)
	{
		membag_free(flow_match13[flow_id]);
		flow_match13[flow_id] = NULL;
	}
	// Copy the last flow to here to fill the gap
	flow_match13[flow_id] = flow_match13[iLastFlow-1];
	ofp13_oxm_match[flow_id] = ofp13_oxm_match[iLastFlow-1];
	ofp13_oxm_inst[flow_id] = ofp13_oxm_inst[iLastFlow-1];
	ofp13_oxm_inst_size[flow_id] = ofp13_oxm_inst_size[iLastFlow - 1];
	// Clear the values from the counters that moved
	flow_match13[iLastFlow-1] = NULL;
	ofp13_oxm_match[iLastFlow-1] = NULL;
	ofp13_oxm_inst[iLastFlow-1] = NULL;
	ofp13_oxm_inst_size[iLastFlow - 1] = 0;
	// Move counters
	memcpy(&flow_counters[flow_id], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
	// Clear the counters from the last flow that was moved
	memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
	iLastFlow --;
	return;
}

/*
*	Remove a flow entry from the flow table (OF 1.0)
*
*	@param flow_id - the index number of the flow to remove
*
*/
void remove_flow10(int flow_id)
{
	// Clear flow counters and actions
	memset(&flow_counters[flow_id], 0, sizeof(struct flows_counter));
	membag_free(flow_match10[flow_id]);
	membag_free(flow_actions10[flow_id]);
	// Copy the last flow to here to fill the gap
	flow_match10[flow_id] = flow_match10[iLastFlow-1];
	flow_actions10[flow_id] = flow_actions10[iLastFlow-1];
	// Clear the pointers to the flows that moved
	flow_match10[iLastFlow-1] = NULL;
	flow_actions10[iLastFlow-1] = NULL;
	// Move the counters
	memcpy(&flow_counters[flow_id], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
	// Clear the counters and action from the last flow that was moved
	memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
	iLastFlow --;
	return;

}

/*
*	Processes flow timeouts
*
*/
void flow_timeouts()
{
	for (int i=0;i<iLastFlow;i++)
	{
		if (flow_counters[i].active == true) // Make sure its an active flow
		{
			if (OF_Version == 1)
			{
				if (&flow_match10[i]->idle_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && ((totaltime/2) - flow_counters[i].lastmatch) >= ntohs(&flow_match10[i]->idle_timeout))
				{
					if (ntohs(flow_match10[i]->flags) &  OFPFF10_SEND_FLOW_REM) flowrem_notif10(i,OFPRR10_IDLE_TIMEOUT);
					// Clear flow counters and actions
					remove_flow10(i);
					iLastFlow --;
					return;
				}

				if (&flow_match10[i]->hard_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && ((totaltime/2) - flow_counters[i].duration) >= ntohs(&flow_match10[i]->hard_timeout))
				{
					if (ntohs(&flow_match10[i]->flags) &  OFPFF10_SEND_FLOW_REM) flowrem_notif10(i,OFPRR10_HARD_TIMEOUT);
					// Clear flow counters and actions
					remove_flow10(i);
					iLastFlow --;
					return;
				}
			} else if (OF_Version == 4)
			{
				if (flow_match13[i]->idle_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && ((totaltime/2) - flow_counters[i].lastmatch) >= ntohs(flow_match13[i]->idle_timeout))
				{
					if (ntohs(flow_match13[i]->flags) &  OFPFF13_SEND_FLOW_REM) flowrem_notif13(i,OFPRR13_IDLE_TIMEOUT);
					remove_flow13(i);
					return;
				}

				if (flow_match13[i]->hard_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && ((totaltime/2) - flow_counters[i].duration) >= ntohs(flow_match13[i]->hard_timeout))
				{
					if (ntohs(flow_match13[i]->flags) &  OFPFF13_SEND_FLOW_REM) flowrem_notif13(i,OFPRR13_HARD_TIMEOUT);
					remove_flow13(i);
					return;
				}
			}
		}
	}
	return;
}

/*
*	Clears the flow table
*
*/
void clear_flows(void)
{
	iLastFlow = 0;
	iLastMeter = 0;
	membag_init();

	/*	Clear OpenFlow 1.0 flow table	*/
	if (OF_Version == 0x01)
	{
		for(int q=0;q<MAX_FLOWS_10;q++)
		{
			memset(&flow_counters[q], 0, sizeof(struct flows_counter));
			if (flow_match10[q] != NULL) flow_match10[q] = NULL;
			if (flow_actions10[q] != NULL) flow_actions10[q] = NULL;
		}
	}
	
	/*	Clear OpenFlow 1.3 flow table	*/
	if (OF_Version == 0x04)
	{
		for(int q=0;q<MAX_FLOWS_13;q++)
		{
			memset(&flow_counters[q], 0, sizeof(struct flows_counter));
			if (ofp13_oxm_match[q] != NULL) ofp13_oxm_match[q] = NULL;
			if (ofp13_oxm_inst[q] != NULL) ofp13_oxm_inst[q] = NULL;
			if (flow_match13[q] != NULL) flow_match13[q] = NULL;
			ofp13_oxm_inst_size[q] = 0;
		}
	}
	
	/*	Clear Table Counters	*/
	for(int x=0; x<MAX_TABLES;x++)
	{
		table_counters[x].lookup_count = 0;
		table_counters[x].matched_count = 0;
	}
	
	/* Clear Meter Table Pointers*/
	for(int x=0; x<MAX_METER_13;x++)
	{
		if(meter_entry[x] != NULL)
		{
			meter_entry[x] = NULL;
		}
	}
	
	/* Clear Groups*/
	for(int x=0; x<MAX_GROUPS;x++)
	{
		group_entry13[x].active = false;
		action_bucket[group_entry13[x].bucket_id-1].active = false;
	}
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
	if ((last - first) > 20) last = first + 20;	// Only show first 20 flows to conserve memory

	for(int k=first; k<last;k++)
	{
		action_hdr1 = flow_actions10[k]->action1;
		action_hdr2 = flow_actions10[k]->action2;
		action_hdr3 = flow_actions10[k]->action3;
		action_hdr4 = flow_actions10[k]->action4;
		stats_size = sizeof(flow_stats);
		flow_stats.table_id = 0;
		memcpy(&flow_stats.match, &flow_match10[k]->match, sizeof(struct ofp_match));
		memcpy(&flow_stats.cookie, &flow_match10[k]->cookie, sizeof(uint64_t));
		memcpy(&flow_stats.priority, flow_match10[k]->priority, sizeof(uint16_t));
		memcpy(&flow_stats.idle_timeout, flow_match10[k]->idle_timeout, sizeof(uint16_t));
		memcpy(&flow_stats.hard_timeout, flow_match10[k]->hard_timeout, sizeof(uint16_t));
		flow_stats.duration_sec = HTONL((totaltime/2) - flow_counters[k].duration);
		flow_stats.duration_nsec = 0;
		flow_stats.packet_count = htonll(flow_counters[k].hitCount);
		flow_stats.byte_count = htonll(flow_counters[k].bytes);
		actionsize = ntohs(action_hdr1->len) + ntohs(action_hdr2->len) + ntohs(action_hdr3->len) + ntohs(action_hdr4->len);
		flow_stats.length = htons(stats_size + actionsize);

		memcpy(buffer + len, &flow_stats, stats_size);
		len += stats_size;

		if(ntohs(action_hdr1->len) > 0)
		{
			memcpy(buffer + len, flow_actions10[k]->action1, ntohs(action_hdr1->len));
			stats_size += ntohs(action_hdr1->len);
			len += ntohs(action_hdr1->len);
		}

		if(ntohs(action_hdr2->len) > 0)
		{
			memcpy(buffer + len, flow_actions10[k]->action2, ntohs(action_hdr2->len));
			stats_size += ntohs(action_hdr2->len);
			len += ntohs(action_hdr2->len);
		}

		if(ntohs(action_hdr3->len) > 0)
		{
			memcpy(buffer + len, flow_actions10[k]->action3, ntohs(action_hdr3->len));
			stats_size += ntohs(action_hdr3->len);
			len += ntohs(action_hdr3->len);
		}

		if(ntohs(action_hdr4->len) > 0)
		{
			memcpy(buffer + len, flow_actions10[k]->action4, ntohs(action_hdr4->len));
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
	char *buffer_ptr = buffer;
	int len;

	for(int k = first; k<last;k++)
	{
		// ofp_flow_stats fixed fields are the same length with ofp_flow_mod
		flow_stats.length = flow_match13[k]->header.length;
		flow_stats.table_id = flow_match13[k]->table_id;
		flow_stats.duration_sec = htonl((totaltime/2) - flow_counters[k].duration);
		flow_stats.duration_nsec = htonl(0);
		flow_stats.priority = flow_match13[k]->priority;
		flow_stats.idle_timeout = flow_match13[k]->idle_timeout;
		flow_stats.hard_timeout = flow_match13[k]->hard_timeout;
		flow_stats.flags = flow_match13[k]->flags;
		flow_stats.cookie = flow_match13[k]->cookie;
		flow_stats.packet_count = htonll(flow_counters[k].hitCount);
		flow_stats.byte_count = htonll(flow_counters[k].bytes);
		flow_stats.match = flow_match13[k]->match;
		// buffer must be shorter than 2048
		if(buffer_ptr + ntohs(flow_stats.length) > buffer + 2048){
			break; // XXX: should provide multipart OFPMPF_REPLY_MORE flow
		}
		// struct ofp13_flow_stats(including ofp13_match)
		memcpy(buffer_ptr, &flow_stats, sizeof(struct ofp13_flow_stats));
		// oxm_fields
		len = offsetof(struct ofp13_flow_stats, match) + offsetof(struct ofp13_match, oxm_fields);
		memcpy(buffer_ptr + len, ofp13_oxm_match[k], ntohs(flow_stats.match.length) - 4);
		// instructions
		len = offsetof(struct ofp13_flow_stats, match) + ALIGN8(ntohs(flow_stats.match.length));
		memcpy(buffer_ptr + len, ofp13_oxm_inst[k], ntohs(flow_stats.length) - len);
		buffer_ptr += ntohs(flow_stats.length);
	}
	return (buffer_ptr - buffer);
}

/*
*	Meter processing for OF 1.3
*
*	@param	id		- meter ID to process
*	@param	bytes	- packet size (for throughput calculations)
*
*	@ret	METER_NOACT	- no action needs to be taken
*	@ret	METER_DROP	- packet needs to be dropped
*	@ret	val			- increase encoded drop precedence by val (DSCP remark)
*
*/
int	meter_handler(uint32_t id, uint16_t bytes)
{
	// Initialise 8x 12-element packet samples
	static struct meter_sample_array meter_samples[MAX_METER_13];
	//static uint16_t sample_index = 0;
	
	TRACE("of_helper.c: meter id %d needs processing", id);
	
	// Get associated meter entry
	int meter_index = 0;
	while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
	{
		if(meter_entry[meter_index]->meter_id == id)
		{
			TRACE("of_helper.c: meter entry found - continuing");
			break;
		}
			
		meter_index++;
	}
	if(meter_entry[meter_index] == NULL || meter_index == MAX_METER_13)
	{
		TRACE("of_helper.c: meter entry not found - packet not dropped");
		return METER_NOACT;
	}
	// meter_index now holds the meter bound to the current flow
	
	// Update meter counters
	meter_entry[meter_index]->byte_in_count += bytes;
	(meter_entry[meter_index]->packet_in_count)++;
	meter_entry[meter_index]->last_packet_in = sys_get_ms();
	
	//// Check if meter has been used before
	//if(meter_entry[meter_index]->last_packet_in == 0)
	//{
		//// Update timer
		//meter_entry[meter_index]->last_packet_in = sys_get_ms();
		//
		//TRACE("of_helper.c: first hit of meter - packet not dropped");
		//return METER_NOACT;
	//}
	
	// Get current time
	uint32_t current_time = (uint32_t)(sys_get_ms());
	
	// Check configuration flags
	uint32_t calculated_rate = 0;
	if(((meter_entry[meter_index]->flags) & OFPMF13_KBPS) == OFPMF13_KBPS)
	{
		// Sum sampled bytes
		uint32_t sampled_bytes = 0;
		for(uint16_t i; i<POLICING_SAMPLES; i++)
		{
			sampled_bytes += meter_samples[meter_index].sample[i].byte_count;
		}
		
		// Find time delta
		uint32_t sample_time = 0;
		if(meter_samples[meter_index].sample_index == POLICING_SAMPLES-1)
		{
			//sample_time = meter_samples[meter_index].sample[sample_index].packet_time - meter_samples[meter_index].sample[0].packet_time;
			sample_time = current_time - meter_samples[meter_index].sample[0].packet_time;
		}
		else
		{
			//sample_time = meter_samples[meter_index].sample[sample_index].packet_time - meter_samples[meter_index].sample[sample_index+1].packet_time;
			sample_time = current_time - meter_samples[meter_index].sample[meter_samples[meter_index].sample_index+1].packet_time;
		}
		
		calculated_rate = ((sampled_bytes*8)/sample_time);	// bit/ms == kbit/s
		TRACE("of_helper.c: calculated rate - %d kbps (%d bytes over %d ms)", calculated_rate, sampled_bytes, sample_time);
	}
	else if(((meter_entry[meter_index]->flags) & OFPMF13_PKTPS) == OFPMF13_PKTPS)
	{
		// Sum sampled packets
		uint16_t sampled_packets = 0;
		for(uint16_t i; i<POLICING_SAMPLES; i++)
		{
			sampled_packets += meter_samples[meter_index].sample[i].packet_count;
		}
		
		// Find time delta
		uint32_t sample_time = 0;
		if(meter_samples[meter_index].sample_index == POLICING_SAMPLES-1)
		{
			//sample_time = meter_samples[meter_index].sample[sample_index].packet_time - meter_samples[meter_index].sample[0].packet_time;
			sample_time = current_time - meter_samples[meter_index].sample[0].packet_time;
		}
		else
		{
			//sample_time = meter_samples[meter_index].sample[sample_index].packet_time - meter_samples[meter_index].sample[sample_index+1].packet_time;
			sample_time = current_time - meter_samples[meter_index].sample[meter_samples[meter_index].sample_index+1].packet_time;
		}
		
		calculated_rate = 1000*sampled_packets/sample_time;		// 1000*pkt/ms == pkt/s
		TRACE("of_helper.c: calculated rate - %d pktps (%d packets over %d ms)", calculated_rate, sampled_packets, sample_time);
	}
	else
	{
		TRACE("of_helper.c: unsupported meter configuration - packet not dropped");
		return METER_NOACT;
	}
	
	// Check each band
	int			bands_processed = 0;
	uint32_t	highest_rate = 0;			// Highest triggered band rate
	struct ofp13_meter_band_drop * ptr_highest_band = NULL;	// Store pointer to highest triggered band
	struct ofp13_meter_band_drop * ptr_band;
	ptr_band = &(meter_entry[meter_index]->bands);
	while(bands_processed < meter_entry[meter_index]->band_count)
	{
		if(calculated_rate >= ptr_band->rate)
		{
			if(ptr_band->rate > highest_rate)
			{
				highest_rate = ptr_band->rate;	// Update highest triggered band rate
				ptr_highest_band = ptr_band;	// Update highest triggered band
			}			
		}
		
		ptr_band++;	// Move to next band
		bands_processed++;
	}
	
	// Check if any bands triggered
	if(highest_rate == 0 || ptr_highest_band == NULL)
	{
		TRACE("of_helper.c: no bands triggered - packet not dropped");
		
		// Check if last packet was within 1 slice of this one
		if(meter_samples[meter_index].sample[meter_samples[meter_index].sample_index].packet_time >= (current_time-POLICING_SLICE-1))
		{
			meter_samples[meter_index].sample[meter_samples[meter_index].sample_index].byte_count += bytes;
			meter_samples[meter_index].sample[meter_samples[meter_index].sample_index].packet_count++;
		}
		else
		{
			// Increment sample index
			if(meter_samples[meter_index].sample_index >= POLICING_SAMPLES-1)
			{
				// Wrap sample_index around
				meter_samples[meter_index].sample_index = 0;
			}
			else
			{
				// Increment index
				meter_samples[meter_index].sample_index++;
			}
		
			// Populate (overwrite) next element
			meter_samples[meter_index].sample[meter_samples[meter_index].sample_index].packet_time = current_time;
			meter_samples[meter_index].sample[meter_samples[meter_index].sample_index].byte_count = bytes;
			meter_samples[meter_index].sample[meter_samples[meter_index].sample_index].packet_count = 0;
		}
		
		return METER_NOACT;
	}
	
	// Check band type
	if(ptr_highest_band->type != OFPMBT13_DROP && ptr_highest_band->type != OFPMBT13_DSCP_REMARK)
	{
		TRACE("of_helper.c: unsupported band type - not dropping packet");
		return METER_NOACT;
	}
	
	TRACE("of_helper.c: highest triggered band rate:%d", highest_rate);
	
	/* Update band counters */
	// Find band index
	int band_index = ((uint8_t*)ptr_highest_band - (uint8_t*)&(meter_entry[meter_index]->bands)) / sizeof(struct ofp13_meter_band_drop);
	
	// Update counters
	band_stats_array[meter_index].band_stats[band_index].byte_band_count += bytes;
	band_stats_array[meter_index].band_stats[band_index].packet_band_count++;

	if(ptr_highest_band->type == OFPMBT13_DROP)
	{
		TRACE("of_helper.c: packet dropped");
		return METER_DROP;
	}
	else if(ptr_highest_band->type == OFPMBT13_DSCP_REMARK)
	{
		struct ofp13_meter_band_dscp_remark * ptr_dscp_band = ptr_highest_band;
		int prec_increase = (int)(ptr_dscp_band->prec_level);
		
		TRACE("of_helper.c: DSCP drop precedence needs to be increased by %d", prec_increase);
		return prec_increase;
	}
	
	TRACE("of_helper.c: ERROR - unknown band type");
	return METER_NOACT;
}

/*
*	Retrieve number of flows bound to the specified meter
*
*	@param	id		- meter ID to check
*
*	@ret	count	- number of associated flows
*
*/
uint32_t get_bound_flows(uint32_t id)
{
	uint32_t count = 0;
	
	// Loop through flows
	for (int i=0;i<iLastFlow;i++)
	{
		void *insts[8] = {0};
		int inst_size = 0;
		while(inst_size < ofp13_oxm_inst_size[i]){
			struct ofp13_instruction *inst_ptr = (struct ofp13_instruction *)(ofp13_oxm_inst[i] + inst_size);
			insts[ntohs(inst_ptr->type)] = inst_ptr;
			inst_size += ntohs(inst_ptr->len);
		}
		
		// Check if metering instruction is present
		if(insts[OFPIT13_METER] != NULL)
		{
			struct ofp13_instruction_meter *inst_meter = insts[OFPIT13_METER];
			// Check the found meter id
			if(ntohl(inst_meter->meter_id) == id)
			{
				// The flow's instruction matches the specified meter id
				count++;	// increment the counter
			}
		}
	}
	
	return count;
}
