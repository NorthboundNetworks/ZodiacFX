/**
 * @file
 * openflow_13.c
 *
 * This file contains the OpenFlow v1.3 (0x04) specific functions
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
#include "trace.h"
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "lwip/tcp.h"
#include "ipv4/lwip/ip.h"
#include "lwip/inet_chksum.h"
#include "timers.h"


#define ALIGN8(x) (x+7)/8*8

// Global variables
extern struct zodiac_config Zodiac_Config;
extern struct tcp_pcb *tcp_pcb;
extern int OF_Version;
extern bool rcv_freq;
extern int iLastFlow;
extern int iLastMeter;
extern int totaltime;
extern struct ofp13_flow_mod *flow_match13[MAX_FLOWS_13];
extern struct meter_entry13 *meter_entry[MAX_METER_13];
extern struct meter_band_stats_array band_stats_array[MAX_METER_13];
extern struct group_entry13 group_entry13[MAX_GROUPS];
extern struct action_bucket action_bucket[MAX_BUCKETS];
extern uint8_t *ofp13_oxm_match[MAX_FLOWS_13];
extern uint8_t *ofp13_oxm_inst[MAX_FLOWS_13];
extern uint16_t ofp13_oxm_inst_size[MAX_FLOWS_13];
extern struct flows_counter flow_counters[MAX_FLOWS_13];
extern struct ofp13_port_stats phys13_port_stats[TOTAL_PORTS];
extern struct table_counter table_counters[MAX_TABLES];
extern uint8_t port_status[TOTAL_PORTS];
extern struct ofp_switch_config Switch_config;
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];
extern uint8_t NativePortMatrix;
extern bool reply_more_flag;
extern uint32_t reply_more_xid;
extern int meter_handler(uint32_t id, uint16_t bytes);

// Internal functions
void features_reply13(uint32_t xid);
void of_error13(struct ofp_header *msg, uint16_t type, uint16_t code);
void set_config13(struct ofp_header * msg);
void config_reply13(uint32_t xid);
void role_reply13(struct ofp_header *msg);
void flow_mod13(struct ofp_header *msg);
void flow_add13(struct ofp_header *msg);
void flow_delete13(struct ofp_header *msg);
void flow_delete_strict13(struct ofp_header *msg);
int multi_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_aggregate_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_portstats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_portdesc_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_table_reply13(uint8_t *buffer, struct ofp13_multipart_request *req);
int multi_tablefeat_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_meter_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_meter_config_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_meter_features_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_group_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_group_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_group_features_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint32_t port, uint8_t reason, int flow);
void packet_out13(struct ofp_header *msg);
void meter_mod13(struct ofp_header *msg);
void meter_add13(struct ofp_header *msg);
void meter_modify13(struct ofp_header *msg);
void meter_delete13(struct ofp_header *msg);
void group_mod13(struct ofp_header *msg);
void group_add13(struct ofp_header *msg);
void group_modify13(struct ofp_header *msg);
void group_delete13(struct ofp_header *msg);



/*
*	Converts a 64bit value from host to network format
*
*	@param n - value to convert.
*
*/
static inline uint64_t (htonll)(uint64_t n)
{
	return HTONL(1) == 1 ? n : ((uint64_t) HTONL(n) << 32) | HTONL(n >> 32);
}

void nnOF13_tablelookup(uint8_t *p_uc_data, uint32_t *ul_size, int port)
{
	uint8_t table_id = 0;
	uint16_t packet_size = (uint16_t)*ul_size;
	struct packet_fields fields = {0};
	packet_fields_parser(p_uc_data, &fields);

	while(1)	// Loop through goto_tables until we get a miss
	{
		table_counters[table_id].lookup_count++;
		// Check if packet matches an existing flow
		int i = flowmatch13(p_uc_data, port, table_id, &fields);
		if(i < 0){
			return;
		}
		TRACE("openflow_13.c: Matched flow %d, table %d", i+1, table_id);
		
		flow_counters[i].hitCount++; // Increment flow hit count
		flow_counters[i].bytes += packet_size;
		flow_counters[i].lastmatch = (totaltime/2); // Increment flow hit count
		table_counters[table_id].matched_count++;
		table_counters[table_id].byte_count += packet_size;

		// If there are no instructions then it's a DROP so just return
		if(ofp13_oxm_inst[i] == NULL) return;

		// Process Instructions
		// The order is Meter -> Apply -> Clear -> Write -> Metadata -> Goto
		void *insts[8] = {0};
		int inst_size = 0;
		while(inst_size < ofp13_oxm_inst_size[i]){
			struct ofp13_instruction *inst_ptr = (struct ofp13_instruction *)(ofp13_oxm_inst[i] + inst_size);
			insts[ntohs(inst_ptr->type)] = inst_ptr;
			inst_size += ntohs(inst_ptr->len);
		}
		
		if(insts[OFPIT13_METER] != NULL)
		{
			struct ofp13_instruction_meter *inst_meter = insts[OFPIT13_METER];
			int meter_ret = meter_handler(ntohl(inst_meter->meter_id), packet_size);
			if(meter_ret == METER_DROP)	// Process meter id (provide byte count for counters)
			{
				// Packet must be dropped
				TRACE("openflow_13.c: dropping packet");
				return;
			}
			else if(meter_ret == METER_NOACT)
			{
				TRACE("openflow_13.c: no action taken");
			}
			else
			{
				if(meter_ret > 0)
				{
					int prec_increase = meter_ret;
					
					if (fields.eth_prot == htons(0x0800))
					{
						TRACE("openflow_13.c: increasing encoded drop precedence by %d", prec_increase);

						// Retrieve TOS field
						struct ip_hdr *hdr = fields.payload;
						uint8_t prec_level = IPH_TOS(hdr);
						TRACE("openflow_13.c: header current TOS field - %d", (int)prec_level);
						// Isolate the drop precedence value (3 bits)
						prec_level = (prec_level & 0x1C) >> 2;
						// Check that value is valid ( 2 || 4 || 6 )
						if( prec_level == 2 || prec_level == 4 || prec_level == 6)
						{
							// Increase drop precedence level by specified value
							TRACE("openflow_13.c: increasing drop precedence level by %d", prec_increase);
							prec_level = 2*(prec_level/2 + prec_increase);
							// Ensure drop precedence value is valid
							if(prec_level > 6)
							{
								prec_level = 6;
							}
							// Write new precedence to TOS field
							TRACE("openflow_13.c: header new TOS field - %d", (prec_level<<2)|(IPH_TOS(hdr)&0xE3))
							IPH_TOS_SET(hdr, (prec_level<<2)|(IPH_TOS(hdr)&0xE3));
													
							// Recalculate IP checksum
							set_ip_checksum(p_uc_data, packet_size, fields.payload + 14);
						}
						else
						{
							TRACE("openflow_13.c: invalid drop precedence value - no adjustments made");
						}

					}
				}
				else
				{
					TRACE("openflow_13.c: ERROR - unhandled meter_handler return value");
				}
			}
		}
			
		if(insts[OFPIT13_APPLY_ACTIONS] != NULL)
		{
			bool recalculate_ip_checksum = false;
			struct ofp13_instruction_actions *inst_actions = insts[OFPIT13_APPLY_ACTIONS];
			int act_size = 0;
			while (act_size < (ntohs(inst_actions->len) - sizeof(struct ofp13_instruction_actions)))
			{
				struct ofp13_action_header *act_hdr = (struct ofp13_action_header*)((uintptr_t)inst_actions->actions + act_size);
				switch (htons(act_hdr->type))
				{
				// Output Action
				case OFPAT13_OUTPUT:
				{
					if(recalculate_ip_checksum){
						set_ip_checksum(p_uc_data, packet_size, fields.payload - p_uc_data);
						recalculate_ip_checksum = false;
					}

					struct ofp13_action_output *act_output = act_hdr;
					if (htonl(act_output->port) < OFPP13_MAX && htonl(act_output->port) != port)
					{
						int outport = (1<< (ntohl(act_output->port)-1));
						TRACE("openflow_13.c: Output to port %d (%d bytes)", ntohl(act_output->port), packet_size);
						gmac_write(p_uc_data, packet_size, outport);
					} else if (htonl(act_output->port) == OFPP13_IN_PORT)
					{
						int outport = (1<< (port-1));
						TRACE("openflow_13.c: Output to in_port %d (%d bytes)", port, packet_size);
						gmac_write(p_uc_data, packet_size, outport);
					} else if (htonl(act_output->port) == OFPP13_CONTROLLER)
					{
						int pisize = ntohs(act_output->max_len);
						if (pisize > packet_size) pisize = packet_size;
						TRACE("openflow_13.c: Output to controller (%d bytes)", packet_size);
						packet_in13(p_uc_data, pisize, port, OFPR_ACTION, i);
					} else if (htonl(act_output->port) == OFPP13_FLOOD || htonl(act_output->port) == OFPP13_ALL)
					{
						int outport = (15 - NativePortMatrix) - (1<<(port-1));
						if (htonl(act_output->port) == OFPP13_FLOOD) TRACE("openflow_13.c: Output to FLOOD (%d bytes)", packet_size);
						if (htonl(act_output->port) == OFPP13_ALL) TRACE("openflow_13.c: Output to ALL (%d bytes)", packet_size);
						gmac_write(p_uc_data, packet_size, outport);
					}
				}
				break;

				// Apply group
				case OFPAT13_GROUP:
				{
					uint8_t act_size = sizeof(struct ofp13_bucket);
					struct ofp13_action_group *act_group = (struct ofp13_action_group*)act_hdr;
					struct ofp13_bucket *bucket_hdr;
					struct ofp13_action_header *act_hdr;
					TRACE("openflow_13.c: Group ID = %d", ntohl(act_group->group_id));
					bucket_hdr = (struct ofp13_bucket *)action_bucket[group_entry13[ntohl(act_group->group_id)-1].bucket_id-1].data;
					TRACE("openflow_13.c: Bucket ID = %d", group_entry13[ntohl(act_group->group_id)-1].bucket_id);
					if (htons(bucket_hdr->len == sizeof(struct ofp13_bucket))) break;   // No actions
					while (act_size < htons(bucket_hdr->len))
					{
						TRACE("openflow_13.c: act_size = %d - bucket length = %d", act_size, htons(bucket_hdr->len));
						act_hdr = (struct ofp13_action_header*)((uintptr_t)bucket_hdr + act_size);
						TRACE("openflow_13.c: Action type = %d", htons(act_hdr->type));
						if (htons(act_hdr->type) == OFPAT13_OUTPUT)
						{
							if(recalculate_ip_checksum){
								set_ip_checksum(p_uc_data, packet_size, fields.payload - p_uc_data);
								recalculate_ip_checksum = false;
							}
							struct ofp13_action_output *act_output = act_hdr;
			                if (htonl(act_output->port) < OFPP13_MAX && htonl(act_output->port) != port)
			                {
								int outport = (1<< (ntohl(act_output->port)-1));
								TRACE("openflow_13.c: Output to port %d (%d bytes)", ntohl(act_output->port), packet_size);
								gmac_write(p_uc_data, packet_size, outport);
			                } else if (htonl(act_output->port) == OFPP13_IN_PORT)
			                {
								int outport = (1<< (port-1));
								TRACE("openflow_13.c: Output to in_port %d (%d bytes)", port, packet_size);
								gmac_write(p_uc_data, packet_size, outport);
			                } else if (htonl(act_output->port) == OFPP13_FLOOD || htonl(act_output->port) == OFPP13_ALL)
			                {
								int outport = (15 - NativePortMatrix) - (1<<(port-1));
								if (htonl(act_output->port) == OFPP13_FLOOD) TRACE("openflow_13.c: Output to FLOOD (%d bytes)", packet_size);
								if (htonl(act_output->port) == OFPP13_ALL) TRACE("openflow_13.c: Output to ALL (%d bytes)", packet_size);
								gmac_write(p_uc_data, packet_size, outport);
			                } else if (htonl(act_output->port) == OFPP13_CONTROLLER)
			                {
								int pisize = ntohs(act_output->max_len);
								if (pisize > packet_size) pisize = packet_size;
								TRACE("openflow_13.c: Output to controller (%d bytes)", packet_size);
								packet_in13(p_uc_data, pisize, port, OFPR_ACTION, i);
			                }
		                }
		                act_size += htons(act_hdr->len);
	                }
                }
                break;

				// Push a VLAN tag
				case OFPAT13_PUSH_VLAN:
				{
					struct ofp13_action_push *push = (struct ofp13_action_push*)act_hdr;
					memmove(p_uc_data+16, p_uc_data+12, packet_size-12);
					memcpy(p_uc_data+12, &push->ethertype, 2);
					if(fields.isVlanTag){
						memcpy(p_uc_data+14, p_uc_data+18, 2);
					}else{
						bzero(p_uc_data+14, 2);
					}
					packet_size += 4;
					*ul_size += 4;
					fields.payload += 4;
					fields.isVlanTag = true;
				}
				break;

				// Pop a VLAN tag
				case OFPAT13_POP_VLAN:
				if(fields.isVlanTag){
					memmove(p_uc_data+12, p_uc_data+16, packet_size-16);
					packet_size -= 4;
					*ul_size -= 4;
					fields.payload -= 4;
					if(fields.payload == p_uc_data+14){
						fields.isVlanTag = false;
					}
				}
				break;

				// Push an MPLS tag
				case OFPAT13_PUSH_MPLS:
				{
					uint8_t mpls[4] = {0, 0, 1, 0}; // zeros with bottom stack bit ON
					if (fields.eth_prot == htons(0x0800)){
						struct ip_hdr *hdr = fields.payload;
						mpls[3] = IPH_TTL(hdr);
					} else if (fields.eth_prot == htons(0x8847) || fields.eth_prot == htons(0x8848)){
						memcpy(mpls, fields.payload, 4);
						mpls[2] &= 0xFE; // clear bottom stack bit
					}
					struct ofp13_action_push *push = (struct ofp13_action_push*)act_hdr;
					memmove(fields.payload + 4, fields.payload, packet_size - 12);
					memcpy(fields.payload - 2, &push->ethertype, 2);
					memcpy(fields.payload, mpls, 4);
					fields.payload += 4;
					packet_size += 4;
					*ul_size += 4;
					packet_fields_parser(p_uc_data, &fields);
				}
				break;

				// Pop an MPLS tag
				case OFPAT13_POP_MPLS:
				if(fields.isMPLSTag){
					struct ofp13_action_pop_mpls *pop = (struct ofp13_action_pop_mpls*)act_hdr;
					memmove(p_uc_data+14, p_uc_data+18, packet_size-16);
					fields.payload -= 4;
					memcpy(fields.payload - 2, &pop->ethertype, 2);
					packet_size -= 4;
					*ul_size -= 4;
					packet_fields_parser(p_uc_data, &fields);
				}
				break;

				// Set MPLS TTL
				case OFPAT13_SET_MPLS_TTL:
				{
					struct ofp13_action_mpls_ttl *act_mpls_ttl = act_hdr;
					if(fields.isMPLSTag)
					{
						p_uc_data[17] = act_mpls_ttl->mpls_ttl;
						fields.mpls_ttl = act_mpls_ttl->mpls_ttl;
						TRACE("Set MPLS TTL %d", fields.mpls_ttl);
					}
				}
				break;

				// Set Field Action
				case OFPAT13_SET_FIELD:
				{
					struct ofp13_action_set_field *act_set_field = act_hdr;
					struct oxm_header13 oxm_header;
					uint8_t oxm_value[8];
					memcpy(&oxm_header, act_set_field->field,4);
					oxm_header.oxm_field = oxm_header.oxm_field >> 1;
					switch(oxm_header.oxm_field)
					{
						// Set VLAN ID
						// The use of a set-field action assumes that the corresponding header field exists in the packet
						case OFPXMT_OFB_VLAN_VID:
						if(fields.isVlanTag){
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
							p_uc_data[14] = (p_uc_data[14] & 0xf0) | (oxm_value[0] & 0x0f);
							p_uc_data[15] = oxm_value[1];
							memcpy(&fields.vlanid, oxm_value, 2);
							TRACE("Set VID %u", (ntohs(fields.vlanid) - OFPVID_PRESENT));
						}
						break;

						case OFPXMT_OFB_VLAN_PCP:
						if(fields.isVlanTag){
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 1);
							p_uc_data[14] = (oxm_value[0]<<5) | (p_uc_data[14] & 0x0f);
							TRACE("Set VLAN_PCP %u", oxm_value[0]);
						}
						break;
						
						// Set MPLS
						// The use of a set-field action assumes that the corresponding header field exists in the packet
						case OFPXMT_OFB_MPLS_LABEL:
						if(fields.eth_prot == htons(0x8847) || fields.eth_prot == htons(0x8848)){
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 4);
							memcpy(&fields.mpls_label, oxm_value, 4);
							uint32_t label = ntohl(fields.mpls_label)<<4;
							label = ntohl(label);
							memcpy(oxm_value, &label, 4);
							p_uc_data[14] = oxm_value[1];
							p_uc_data[15] = oxm_value[2];
							p_uc_data[16] |= oxm_value[3];
							TRACE("Set MPLS Label %u", ntohl(fields.mpls_label));
						}
						break;

						case OFPXMT_OFB_MPLS_TC:
						if(fields.eth_prot == htons(0x8847) || fields.eth_prot == htons(0x8848)){
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 1);
							p_uc_data[16] |= (oxm_value[0]<<1);
							memcpy(&fields.mpls_tc, oxm_value, 1);
							TRACE("Set MPLS TC %d", fields.mpls_tc);
						}
						break;

						case OFPXMT_OFB_MPLS_BOS:
						if(fields.eth_prot == htons(0x8847) || fields.eth_prot == htons(0x8848)){
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 1);
							if (oxm_value[0] == 1) p_uc_data[16] |= 1;
							if (oxm_value[0] == 0) p_uc_data[16] &= 0;
							memcpy(&fields.mpls_bos, oxm_value, 1);
							TRACE("Set MPLS %u", fields.mpls_bos);
						}
						break;

						// Set Source Ethernet Address
						case OFPXMT_OFB_ETH_SRC:
						memcpy(p_uc_data + 6, act_set_field->field + sizeof(struct oxm_header13), 6);
						break;
						// Set Destination Ethernet Address
						case OFPXMT_OFB_ETH_DST:
						memcpy(p_uc_data, act_set_field->field + sizeof(struct oxm_header13), 6);
						break;

						// Set Ether Type
						case OFPXMT_OFB_ETH_TYPE:
						memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
						memcpy(fields.payload-2, oxm_value, 2);
						memcpy(&fields.eth_prot, oxm_value, 2);
						break;

						case OFPXMT_OFB_IP_DSCP:
						if (fields.eth_prot == htons(0x0800))
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 1);
							struct ip_hdr *hdr = fields.payload;
							IPH_TOS_SET(hdr, (oxm_value[0]<<2)|(IPH_TOS(hdr)&0x3));
							recalculate_ip_checksum = true;
							TRACE("openflow_13.c: Set IP_DSCP %u", oxm_value[0]);
						}// TODO: IPv6
						break;

						case OFPXMT_OFB_IP_ECN:
						if (fields.eth_prot == htons(0x0800))
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 1);
							struct ip_hdr *hdr = fields.payload;
							IPH_TOS_SET(hdr, (oxm_value[0]&0x3)|(IPH_TOS(hdr)&0xFC));
							recalculate_ip_checksum = true;
							TRACE("openflow_13.c: Set IP_ECN %u", oxm_value[0]);
						}// TODO: IPv6
						break;

						// Set IP protocol
						case OFPXMT_OFB_IP_PROTO:
						if (fields.eth_prot == htons(0x0800))	// IPv4 packet
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
							memcpy(fields.payload + 9, oxm_value, 2);
							memcpy(&fields.ip_prot, oxm_value, 2);
							recalculate_ip_checksum = true;
						}
						// TODO: or IPv6
						break;

						// Set Source IP Address
						case OFPXMT_OFB_IPV4_SRC:
						if (fields.eth_prot == htons(0x0800))	// Only set the field if it is an IPv4 packet
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 4);
							memcpy(fields.payload + 12, oxm_value, 4);
							memcpy(&fields.ip_src, oxm_value, 4);
							recalculate_ip_checksum = true;
						}
						break;

						// Set Destination IP Address
						case OFPXMT_OFB_IPV4_DST:
						if (fields.eth_prot == htons(0x0800))	// Only set the field if it is an IPv4 packet
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 4);
							memcpy(fields.payload + 16, act_set_field->field + sizeof(struct oxm_header13), 4);
							memcpy(&fields.ip_dst, act_set_field->field + sizeof(struct oxm_header13), 4);
							recalculate_ip_checksum = true;
						}
						break;

						// Set Source TCP port
						case OFPXMT_OFB_TCP_SRC:
						if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IP_PROTO_TCP)	// Only set the field if it is an IPv4 TCP packet
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
							memcpy(fields.payload + 20, oxm_value, 2);
							memcpy(&fields.tp_src, oxm_value, 2);
							recalculate_ip_checksum = true;
						}
						break;

						// Set Destination TCP port
						case OFPXMT_OFB_TCP_DST:
						if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IP_PROTO_TCP)	// Only set the field if it is an IPv4 TCP packet
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
							memcpy(fields.payload + 22, oxm_value, 2);
							memcpy(&fields.tp_dst, oxm_value, 2);
							recalculate_ip_checksum = true;
						}
						break;

						// Set Source UDP port
						case OFPXMT_OFB_UDP_SRC:
						if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IP_PROTO_UDP)	// Only set the field if it is an IPv4 UDP packet
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
							memcpy(fields.payload + 20, oxm_value, 2);
							memcpy(&fields.tp_src, oxm_value, 2);
							recalculate_ip_checksum = true;
						}
						break;

						// Set Destination UDP port
						case OFPXMT_OFB_UDP_DST:
						if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IP_PROTO_UDP)	// Only set the field if it is an IPv4 UDP packet
						{
							memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
							memcpy(fields.payload + 22, oxm_value, 2);
							memcpy(&fields.tp_dst, oxm_value, 2);
							recalculate_ip_checksum = true;
						}
						break;

						// Set ICMP type
						case OFPXMT_OFB_ICMPV4_TYPE:
						if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IP_PROTO_ICMP)	// Only set the field if it is an ICMP packet
						{
							struct ip_hdr *iphdr = fields.payload;
							uint8_t *icmp = fields.payload + IPH_HL(iphdr) * 4;
							memcpy(icmp, act_set_field->field + sizeof(struct oxm_header13), 1);
							recalculate_ip_checksum = true;
						}
						break;

						// Set ICMP code
						case OFPXMT_OFB_ICMPV4_CODE:
						if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IP_PROTO_ICMP)	// Only set the field if it is an ICMP packet
						{
							struct ip_hdr *iphdr = fields.payload;
							uint8_t *icmp = fields.payload + IPH_HL(iphdr) * 4;
							memcpy(icmp+1, act_set_field->field + sizeof(struct oxm_header13), 1);
							recalculate_ip_checksum = true;
						}
						break;

						// Set ARP opcode
						case OFPXMT_OFB_ARP_OP:
						if (fields.eth_prot == htons(0x0806))	// Only set the field if it is a ARP packet
						{
							memcpy(fields.payload + 6, act_set_field->field + sizeof(struct oxm_header13), 2);
						}
						break;

						// Set ARP source IP address
						case OFPXMT_OFB_ARP_SPA:
						if (fields.eth_prot == htons(0x0806))	// Only set the field if it is an ARP packet
						{
							memcpy(fields.payload + 14, act_set_field->field + sizeof(struct oxm_header13), 4);
						}
						break;

						// Set ARP target IP address
						case OFPXMT_OFB_ARP_TPA:
						if (fields.eth_prot == htons(0x0806))	// Only set the field if it is an ARP packet
						{
							memcpy(fields.payload + 24, act_set_field->field + sizeof(struct oxm_header13), 4);
						}
						break;

						// Set ARP source hardware address
						case OFPXMT_OFB_ARP_SHA:
						if (fields.eth_prot == htons(0x0806))	// Only set the field if it is an ARP packet
						{
							memcpy(fields.payload + 8, act_set_field->field + sizeof(struct oxm_header13), 6);
						}
						break;

						// Set ARP target hardware address
						case OFPXMT_OFB_ARP_THA:
						if (fields.eth_prot == htons(0x0806))	// Only set the field if it is an ARP packet
						{
							memcpy(fields.payload + 18, act_set_field->field + sizeof(struct oxm_header13), 6);
						}
						break;
					}
				}
				}
				act_size += htons(act_hdr->len);
			}

			if (recalculate_ip_checksum) {
				set_ip_checksum(p_uc_data, packet_size, fields.payload - p_uc_data);
			}
		}
			
		if(insts[OFPIT13_GOTO_TABLE] != NULL)
		{
			struct ofp13_instruction_goto_table *inst_goto_ptr = insts[OFPIT13_GOTO_TABLE];
			if (table_id >= inst_goto_ptr->table_id) {
				TRACE("openflow_13.c: Goto loop detected, aborting (cannot goto to earlier/same table)");
				return;
			}
			table_id = inst_goto_ptr->table_id;
			TRACE("openflow_13.c: Goto table %d", table_id);
		}
		else
		{
			return;
		}
	}
	return;
}

void of13_message(struct ofp_header *ofph, int len)
{
	struct ofp13_multipart_request *multi_req;
	int multi_len;

	TRACE("openflow_13.c: %u: OpenFlow message received type = %d", htonl(ofph->xid), ofph->type);
	switch(ofph->type)
	{
		case OFPT13_FEATURES_REQUEST:
		rcv_freq = true;
		features_reply13(ofph->xid);
		break;

		case OFPT13_SET_CONFIG:
		set_config13(ofph);
		break;

		case OFPT13_GET_CONFIG_REQUEST:
		config_reply13(ofph->xid);
		break;

		case OFPT13_ROLE_REQUEST:
		role_reply13(ofph);
		break;

		case OFPT13_FLOW_MOD:
		flow_mod13(ofph);
		break;

		case OFPT13_GROUP_MOD:
		group_mod13(ofph);
		break;


		case OFPT13_MULTIPART_REQUEST:
		multi_req  = (struct ofp13_multipart_request *) ofph;
		if(multi_req->flags != 0)
		{
			TRACE("openflow_13.c: unsupported MULTIPART 'flags' request: %04x", multi_req->flags);
			return;
		}

		if ( ntohs(multi_req->type) == OFPMP13_DESC )
		{
			multi_len = multi_desc_reply13(shared_buffer, multi_req);
		}

		if ( ntohs(multi_req->type) == 	OFPMP13_FLOW )
		{
			multi_len = multi_flow_reply13(shared_buffer, multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_AGGREGATE )
		{
			multi_len = multi_aggregate_reply13(shared_buffer, multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_PORT_STATS )
		{
			multi_len = multi_portstats_reply13(shared_buffer, multi_req);
		}

		if ( ntohs(multi_req->type) == OFPMP13_PORT_DESC )
		{
			multi_len = multi_portdesc_reply13(shared_buffer, multi_req);
		}

		if ( ntohs(multi_req->type) == OFPMP13_METER )
		{
			multi_len = multi_meter_stats_reply13(shared_buffer, multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_METER_CONFIG )
		{
			multi_len = multi_meter_config_reply13(shared_buffer, multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_METER_FEATURES )
		{
			multi_len = multi_meter_features_reply13(shared_buffer, multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_GROUP_FEATURES )
		{
			multi_len = multi_group_features_reply13(shared_buffer, multi_req);
		}

		if ( ntohs(multi_req->type) == OFPMP13_GROUP_DESC )
		{
			multi_len = multi_group_desc_reply13(shared_buffer, multi_req);
		}

		if ( ntohs(multi_req->type) == OFPMP13_GROUP )
		{
			multi_len = multi_group_stats_reply13(shared_buffer, multi_req);
		}

		if ( htons(multi_req->type) == OFPMP13_TABLE_FEATURES )
		{
			/**** Floodlight v1.2 crashes when it gets this reply, removed for the moment. *****/
			multi_len = multi_tablefeat_reply13(shared_buffer, multi_req);
			//of_error13(ofph, OFPET13_BAD_REQUEST, OFPBRC13_BAD_TYPE);
		}

		if ( ntohs(multi_req->type) == OFPMP13_TABLE )
		{
			multi_len = multi_table_reply13(shared_buffer, multi_req);
		}


		if (multi_len !=0)
		{
			sendtcp(shared_buffer, multi_len, 0);
		}
		break;

		case OFPT10_PACKET_OUT:
		packet_out13(ofph);
		break;

		case OFPT13_BARRIER_REQUEST:
		barrier13_reply(ofph->xid);
		break;
		
		case OFPT13_METER_MOD:
		meter_mod13(ofph);
		break;
	};
	return;
}

/*
*	OpenFlow FEATURE Reply message function
*
*	@param xid - transaction ID
*
*/
void features_reply13(uint32_t xid)
{
	uint64_t datapathid = 0;
	struct ofp13_switch_features features;
	uint8_t buf[256];
	int bufsize = sizeof(struct ofp13_switch_features);
	features.header.version = OF_Version;
	features.header.type = OFPT13_FEATURES_REPLY;
	features.header.length = HTONS(bufsize);
	features.header.xid = xid;
	memcpy(&datapathid, &Zodiac_Config.MAC_address, 6);
	features.datapath_id = datapathid << 16;
	features.n_buffers = htonl(0);		// Number of packets that can be buffered
	features.n_tables = MAX_TABLES;		// Number of flow tables
	features.capabilities = htonl(OFPC13_FLOW_STATS + OFPC13_TABLE_STATS + OFPC13_PORT_STATS + OFPC13_GROUP_STATS);	// Switch Capabilities
	features.auxiliary_id = 0;	// Primary connection

	memcpy(&buf, &features, sizeof(struct ofp13_switch_features));
	sendtcp(&buf, bufsize, 1);
	return;
}

/*
*	OpenFlow SET CONFIG message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void set_config13(struct ofp_header *msg)
{
	struct ofp_switch_config * sc;
	sc = (struct ofp_switch_config *) msg;
	memcpy(&Switch_config, sc, sizeof(struct ofp_switch_config));
	return;
}

/*
*	OpenFlow CONFIG Reply message function
*
*	@param xid - transaction ID
*
*/
void config_reply13(uint32_t xid)
{
	struct ofp13_switch_config cfg_reply;
	cfg_reply.header.version = OF_Version;
	cfg_reply.header.type = OFPT13_GET_CONFIG_REPLY;
	cfg_reply.header.xid = xid;
	cfg_reply.header.length = HTONS(sizeof(cfg_reply));
	cfg_reply.flags = OFPC13_FRAG_NORMAL;
	cfg_reply.miss_send_len = htons(256);	// Only sending the first 256 bytes
	sendtcp(&cfg_reply, sizeof(cfg_reply), 1);
	return;
}

/*
*	OpenFlow SET CONFIG message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void role_reply13(struct ofp_header *msg)
{
	struct ofp13_role_request role_request;
	memcpy(&role_request, msg, sizeof(struct ofp13_role_request));
	role_request.header.type = OFPT13_ROLE_REPLY;
	role_request.generation_id = 0;
	role_request.role = htonl(OFPCR_ROLE_MASTER);
	sendtcp(&role_request, sizeof(struct ofp13_role_request), 1);
	return;
}

/*
*	OpenFlow Multi-part DESCRIPTION reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	const struct ofp13_desc zodiac_desc = {
		.mfr_desc = "Northbound Networks",
		.hw_desc  = "Zodiac-FX Rev.A",
		.sw_desc  = VERSION,
		.serial_num= "none",
		.dp_desc  = "World's smallest OpenFlow switch!"
	};
	struct ofp13_multipart_reply *reply;
	uint16_t len = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_desc);
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.length = htons(len);
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_DESC);
	memcpy(reply->body, &zodiac_desc, sizeof(zodiac_desc));
	return len;
}

/*
*	OpenFlow Multi-part FLOW reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	int len = 0;
	char statsbuffer[2048];
	struct ofp13_multipart_reply *reply;
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_FLOW);
	if(iLastFlow > 15)
	{
		// Only send first 15 flows
		len = flow_stats_msg13(&statsbuffer, 0, 15);
		reply->flags = htons(OFPMPF13_REPLY_MORE);		// More replies will follow
		reply_more_flag = true;					// Notify of_sent that more messages need to be sent
		reply_more_xid = msg->header.xid;		// Store xid for later replies
	}
	else
	{
		// Send all flows
		len = flow_stats_msg13(&statsbuffer, 0, iLastFlow);
	}
	memcpy(reply->body, &statsbuffer, len);
	len += 	sizeof(struct ofp13_multipart_reply);
	reply->header.length = htons(len);
	return len;
}

/*
*	OpenFlow reply more stats function
*
*	@param xid - transaction ID
*
*/
void multi_flow_more_reply13(void)
{
	uint16_t sndbuf = tcp_sndbuf(tcp_pcb);
	if(sndbuf < 2048)
	{
		TRACE("openflow_13.c: waiting to reply with more flows, sndbuf @ %d", sndbuf);
		return;
	}
	
	// Clear shared_buffer
	memset(&shared_buffer, 0, SHARED_BUFFER_LEN);
	
	static int startFlow = 15;
	int len = 0;
	char statsbuffer[2048];
	struct ofp13_multipart_reply *reply;
	reply = (struct ofp13_multipart_reply *) shared_buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.xid = reply_more_xid;
	reply->type = htons(OFPMP13_FLOW);
	if((startFlow+15) < iLastFlow)
	{
		// Send first 15 flows
		TRACE("openflow_13.c: writing flow stats: %d to %d", startFlow, (startFlow+15));
		len = flow_stats_msg13(&statsbuffer, startFlow, (startFlow+15));
		reply->flags = htons(OFPMPF13_REPLY_MORE);		// More replies will follow
		reply_more_flag = true;					// Notify of_sent that more messages need to be sent
		startFlow += 15;
	}
	else
	{
		// Finish sending flows
		TRACE("openflow_13.c: writing final flow stats: %d to %d", startFlow, iLastFlow);
		len = flow_stats_msg13(&statsbuffer, startFlow, iLastFlow);
		reply->flags = 0;						// No more replies will follow
		reply_more_flag = false;				// Notify of_sent that no more messages need to be sent
		reply_more_xid = 0;						// Clear stored xid
		startFlow = 15;							// Reset startFlow
	}
	memcpy(reply->body, &statsbuffer, len);
	len += 	sizeof(struct ofp13_multipart_reply);
	reply->header.length = htons(len);
	
	if (len < 2048)
	{
		TRACE("openflow_13.c: sending flow stats");
		sendtcp(&shared_buffer, len, 0);
	}
	return;
}

/*
*	OpenFlow Multi-part AGGREGATE reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_aggregate_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{ 
	// Add up the required return values
	uint64_t total_packets = 0;
	uint64_t total_bytes = 0;
	for(int i=0; i<iLastFlow; i++)
	{
		if (flow_counters[i].active == true)	// Need to add filters, currently includes all flows
		{
			total_bytes += flow_counters[i].bytes;
			total_packets += flow_counters[i].hitCount;
		}
	}	
	struct ofp13_multipart_reply *reply;
	struct ofp13_aggregate_stats_reply aggregate_reply;
	uint16_t len = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_aggregate_stats_reply);
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_AGGREGATE);
	aggregate_reply.packet_count = htonll(total_packets);
	aggregate_reply.byte_count = htonll(total_bytes);
	aggregate_reply.flow_count = htonl(iLastFlow);
	memcpy(reply->body, &aggregate_reply, sizeof(aggregate_reply));
	reply->header.length = htons(len);
	return len;
}

/*
*	OpenFlow Multi-part PORT Description reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_portdesc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	int numofports = 0;
	for(int n=0;n<TOTAL_PORTS;n++)
	{
		if(Zodiac_Config.of_port[n]==1) numofports++;
	}
	struct ofp13_multipart_reply *reply;
	struct ofp13_port phys_port[numofports];
	uint16_t len = sizeof(struct ofp13_multipart_reply) + sizeof(phys_port);
	int j = 0;
	char portname[8];
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.length = htons(len);
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_PORT_DESC);

	uint8_t mac[] = {0x00,0x00,0x00,0x00,0x00,0x00};
	update_port_status();		//update port status

	for(int l = 0; l<TOTAL_PORTS; l++)
	{
		if(Zodiac_Config.of_port[l] == 1)
		{
			phys_port[j].port_no = htonl(l+1);
			for(int k = 0; k<6; k++)            // Generate random MAC address
			{
				int r = rand() % 255;
				memset(mac + k,r,1);
			}
			memcpy(&phys_port[j].hw_addr, mac, sizeof(mac));
			memset(phys_port[j].name, 0, OFP13_MAX_PORT_NAME_LEN);	// Zero out the name string
			sprintf(portname, "eth%d",l);
			strcpy(phys_port[j].name, portname);
			phys_port[j].config = 0;
			if (port_status[j] == 1) phys_port[j].state = htonl(OFPPS13_LIVE);
			if (port_status[j] == 0) phys_port[j].state = htonl(OFPPS13_LINK_DOWN);
			phys_port[j].curr = htonl(OFPPF13_100MB_FD + OFPPF13_COPPER);
			phys_port[j].advertised = 0;
			phys_port[j].supported = 0;
			phys_port[j].peer = 0;
			phys_port[j].curr_speed = 0;
			phys_port[j].max_speed = 0;
			j ++;
		}
	}

	memcpy(reply->body, &phys_port[0],sizeof(phys_port));
	return len;
}

/*
*	OpenFlow Multi-part TABLE reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_table_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	int len = offsetof(struct ofp13_multipart_reply, body) + sizeof(struct ofp13_table_stats) * MAX_TABLES;
	if (SHARED_BUFFER_LEN < len) { // guard for buffer overrun
		TRACE("openflow_13.c: multi-table reply space exceeded, ignoring");
		return 0;
	}
	bzero(buffer, len);
	struct ofp13_multipart_reply *reply = buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.length = htons(len);
	reply->header.xid = msg->header.xid;
	reply->type = htons(OFPMP13_TABLE);
	reply->flags = 0;
	
	struct ofp13_table_stats *stats = reply->body;
	for(uint8_t table_id=0; table_id<MAX_TABLES; table_id++){
		uint32_t active = 0;
		for(int i=0; i<iLastFlow; i++) {
			if (flow_counters[i].active == true && flow_match13[i]->table_id==table_id){
				active++;
			}
		}
		stats->table_id = table_id;
		stats->active_count = htonl(active);
		stats->matched_count = htonll(table_counters[table_id].matched_count);
		stats->lookup_count = htonll(table_counters[table_id].lookup_count);
		stats++;
	}
	return len;
}

/*
*	OpenFlow Multi-part TABLE Features reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_tablefeat_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	struct ofp13_multipart_reply *reply;
	struct ofp13_table_features tbl_feats;
	struct ofp13_table_feature_prop_instructions inst_prop;
	struct ofp13_instruction inst;
	struct oxm_header13 oxm_header;
	int prop_size = (14*8);

	char tablename[OFP13_MAX_TABLE_NAME_LEN];
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_TABLE_FEATURES);

	tbl_feats.table_id = 0;
	sprintf(tablename, "table_0");
	strcpy(tbl_feats.name, tablename);
	tbl_feats.metadata_match = 0;
	tbl_feats.metadata_write = 0;
	tbl_feats.config = 0;
	tbl_feats.max_entries = htonl(MAX_FLOWS_13);
	int len = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_table_features) + prop_size;
	reply->header.length = htons(len);
	tbl_feats.length = htons(sizeof(struct ofp13_table_features) + prop_size);
	memcpy(reply->body, &tbl_feats, sizeof(struct ofp13_table_features));

	// Instruction Property
 	inst_prop.type = htons(OFPTFPT_INSTRUCTIONS);
 	inst_prop.length = htons(8);
 	inst.type = htons(OFPIT13_APPLY_ACTIONS);
 	inst.len = htons(4);
	memcpy(buffer + (len-(prop_size)), &inst_prop, 4);
	memcpy(buffer + (len-(prop_size-4)), &inst, 4);
	// Next Table Property
	inst_prop.type = htons(OFPTFPT_NEXT_TABLES);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-8)), &inst_prop, 4);
	// Write Actions Property
	inst_prop.type = htons(OFPTFPT_WRITE_ACTIONS);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-16)), &inst_prop, 4);
	// Apply Actions Property
	inst_prop.type = htons(OFPTFPT_APPLY_ACTIONS);
	inst_prop.length = htons(8);
 	inst.type = htons(OFPAT13_OUTPUT);
 	inst.len = htons(4);
	memcpy(buffer + (len-(prop_size-24)), &inst_prop, 4);
	memcpy(buffer + (len-(prop_size-28)), &inst, 4);
	// Match Property
	inst_prop.type = htons(OFPTFPT_MATCH);
	inst_prop.length = htons(52);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-32)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT_OFB_IN_PORT << 1;
	memcpy(buffer + (len-(prop_size-36)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_ETH_DST << 1;
	memcpy(buffer + (len-(prop_size-40)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_ETH_SRC << 1;
	memcpy(buffer + (len-(prop_size-44)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_ETH_TYPE << 1;
	memcpy(buffer + (len-(prop_size-48)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_VLAN_VID << 1;
	memcpy(buffer + (len-(prop_size-52)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_IP_PROTO << 1;
	memcpy(buffer + (len-(prop_size-56)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_IPV4_SRC << 1;
	memcpy(buffer + (len-(prop_size-60)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_IPV4_DST << 1;
	memcpy(buffer + (len-(prop_size-64)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_TCP_SRC << 1;
	memcpy(buffer + (len-(prop_size-68)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_TCP_DST << 1;
	memcpy(buffer + (len-(prop_size-72)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_UDP_SRC << 1;
	memcpy(buffer + (len-(prop_size-76)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT_OFB_UDP_DST << 1;
	memcpy(buffer + (len-(prop_size-80)), &oxm_header, 4);
	// Wildcard Property
	inst_prop.type = htons(OFPTFPT_WILDCARDS);
	inst_prop.length = htons(8);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-88)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT_OFB_IN_PORT << 1;
	memcpy(buffer + (len-(prop_size-92)), &oxm_header, 4);
	// Write set field Property
	inst_prop.type = htons(OFPTFPT_WRITE_SETFIELD);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-96)), &inst_prop, 4);
	// Apply set field Property
	inst_prop.type = htons(OFPTFPT_APPLY_SETFIELD);
	inst_prop.length = htons(8);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-104)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT_OFB_VLAN_VID << 1;
	memcpy(buffer + (len-(prop_size-108)), &oxm_header, 4);
	// !!Need to add additional set field values!!
	return len;
}

/*
*	OpenFlow Multi-part PORT Stats reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_portstats_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	struct ofp13_multipart_reply reply;
	struct ofp13_port_stats zodiac_port_stats;
	struct ofp13_port_stats_request *port_req = msg->body;
	int stats_size = 0;
	int len = 0;
	uint32_t port = ntohl(port_req->port_no);

	if (port == OFPP13_ANY)
	{
		// Find number of OpenFlow ports present
		uint8_t ofports = 0;
		for(uint8_t k=0; k<TOTAL_PORTS; k++)
		{
			// Check if port is NOT native
			if(!(NativePortMatrix & (1<<(k))))
			{
				ofports++;
			}
		}
		
		stats_size = (sizeof(struct ofp13_port_stats) * ofports);	// Calculate length of stats
		len = sizeof(struct ofp13_multipart_reply) + stats_size;	// Calculate total reply length
		
		// Format reply header
		reply.header.version = OF_Version;
		reply.header.type = OFPT13_MULTIPART_REPLY;
		reply.header.length = htons(len);
		reply.header.xid = msg->header.xid;
		reply.type = htons(OFPMP13_PORT_STATS);
		reply.flags = 0;
		
		// Write reply header to buffer
		memcpy(buffer, &reply, sizeof(struct ofp13_multipart_reply));
		// Increment buffer pointer
		buffer += sizeof(struct ofp13_multipart_reply);
		
		// Write port stats to reply message
		for(uint8_t k=0; k<TOTAL_PORTS; k++)
		{
			// Check if port is NOT native
			if(!(NativePortMatrix & (1<<(k))))
			{
				// Format port stats reply for this port
				zodiac_port_stats.port_no = htonl(k+1);
				zodiac_port_stats.rx_packets = htonll(phys13_port_stats[k].rx_packets);
				zodiac_port_stats.tx_packets = htonll(phys13_port_stats[k].tx_packets);
				zodiac_port_stats.rx_bytes = htonll(phys13_port_stats[k].rx_bytes);
				zodiac_port_stats.tx_bytes = htonll(phys13_port_stats[k].tx_bytes);
				zodiac_port_stats.rx_crc_err = htonll(phys13_port_stats[k].rx_crc_err);
				zodiac_port_stats.rx_dropped = htonll(phys13_port_stats[k].rx_dropped);
				zodiac_port_stats.tx_dropped = htonll(phys13_port_stats[k].tx_dropped);
				zodiac_port_stats.rx_frame_err = 0;
				zodiac_port_stats.rx_over_err = 0;
				zodiac_port_stats.tx_errors = 0;
				zodiac_port_stats.rx_errors = 0;
				zodiac_port_stats.collisions = 0;

				if((buffer + sizeof(struct ofp13_port_stats)) < (shared_buffer + SHARED_BUFFER_LEN))
				{
					// Write port stats to buffer
					memcpy(buffer, &zodiac_port_stats, sizeof(struct ofp13_port_stats));
					// Increment buffer pointer
					buffer += sizeof(struct ofp13_port_stats);
				}
				else
				{
					TRACE("openflow_13.c: unable to write port stats to shared buffer");
				}
			}
		}
	}
	else if (port > 0 && port <= TOTAL_PORTS)	// Respond to request for ports
	{
		// Check if port is NOT native
		if(!(NativePortMatrix & (1<<(port-1))))
		{
			stats_size = sizeof(struct ofp13_port_stats);
			len = sizeof(struct ofp13_multipart_reply) + stats_size;

			reply.header.version = OF_Version;
			reply.header.type = OFPT13_MULTIPART_REPLY;
			reply.header.length = htons(len);
			reply.header.xid = msg->header.xid;
			reply.type = htons(OFPMP13_PORT_STATS);
			reply.flags = 0;

			zodiac_port_stats.port_no = htonl(port);
			zodiac_port_stats.rx_packets = htonll(phys13_port_stats[port-1].rx_packets);
			zodiac_port_stats.tx_packets = htonll(phys13_port_stats[port-1].tx_packets);
			zodiac_port_stats.rx_bytes = htonll(phys13_port_stats[port-1].rx_bytes);
			zodiac_port_stats.tx_bytes = htonll(phys13_port_stats[port-1].tx_bytes);
			zodiac_port_stats.rx_crc_err = htonll(phys13_port_stats[port-1].rx_crc_err);
			zodiac_port_stats.rx_dropped = htonll(phys13_port_stats[port-1].rx_dropped);
			zodiac_port_stats.tx_dropped = htonll(phys13_port_stats[port-1].tx_dropped);
			zodiac_port_stats.rx_frame_err = 0;
			zodiac_port_stats.rx_over_err = 0;
			zodiac_port_stats.tx_errors = 0;
			zodiac_port_stats.rx_errors = 0;
			zodiac_port_stats.collisions = 0;

			memcpy(buffer, &reply, sizeof(struct ofp13_multipart_reply));
			memcpy(buffer+sizeof(struct ofp13_multipart_reply), &zodiac_port_stats, stats_size);
		}
		else
		{
			TRACE("openflow_13.c: requested port is out of range");
			of_error13(buffer, OFPET13_BAD_REQUEST, OFPBRC13_BAD_PORT);
		}
	}
	else
	{
		TRACE("openflow_13.c: requested port is out of range");
		of_error13(buffer, OFPET13_BAD_REQUEST, OFPBRC13_BAD_PORT);
	}
	return len;
}

/*
*	Main OpenFlow Meter Statistics message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_meter_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req)
{
	struct ofp13_meter_stats meter_stats;
	struct ofp13_multipart_reply reply;
	struct ofp13_meter_multipart_request *meter_stats_req = req->body;
	uint32_t req_id = ntohl(meter_stats_req->meter_id);
	uint8_t *buffer_ptr = buffer;
		
	if(req_id == OFPM13_ALL)
	{
		TRACE("openflow_13.c: request for all meter statistics");

		/* Reply with all meter stats*/
		
		// Count the number of meters configured, and the total number of bands
		int meter_index = 0;
		uint16_t bands_counter = 0;
		while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
		{
			bands_counter += meter_entry[meter_index]->band_count;
			meter_index++;
		};
		
		TRACE("openflow_13.c: %d meters in meter table, %d bands", meter_index, (int)bands_counter);
				
		// Calculate total size - replysize + (number of meters)*statssize + (total number of bands)*bandsize
		uint16_t	total_size = sizeof(struct ofp13_multipart_reply) + (meter_index*sizeof(struct ofp13_meter_stats)) + (bands_counter*sizeof(struct ofp13_meter_band_stats));
					
		// Format reply
		reply.type				= htons(OFPMP13_METER);
		reply.flags				= 0;	// Single reply
					
		// Format header
		reply.header.version	= OF_Version;
		reply.header.type		= OFPT13_MULTIPART_REPLY;
		reply.header.length		= htons(total_size);
		reply.header.xid		= req->header.xid;
		
		// Copy reply
		memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
		buffer_ptr += sizeof(struct ofp13_multipart_reply);
		
		meter_index = 0;
		// Loop & format each meter stats reply
		while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
		{
			// Format reply with specified meter statistics
			meter_stats.meter_id		= htonl(meter_entry[meter_index]->meter_id);
			meter_stats.len				= htons(sizeof(struct ofp13_meter_stats) + (meter_entry[meter_index]->band_count*sizeof(struct ofp13_meter_band_stats)));
			
			meter_entry[meter_index]->flow_count = get_bound_flows(req_id);
			meter_stats.flow_count		= htonl(meter_entry[meter_index]->flow_count);
			
			meter_stats.packet_in_count = htonll(meter_entry[meter_index]->packet_in_count);
			meter_stats.byte_in_count	= htonll(meter_entry[meter_index]->byte_in_count);
			meter_stats.duration_sec	= htonl((sys_get_ms()-meter_entry[meter_index]->time_added)/1000);
			meter_stats.duration_nsec	= 0;	// nanosecond accuracy unsupported

			// Copy configuration
			memcpy(buffer_ptr, &meter_stats, sizeof(struct ofp13_meter_stats));
			buffer_ptr += sizeof(struct ofp13_meter_stats);
			
			// Format bands
			int bands_processed = 0;
			struct ofp13_meter_band_stats * ptr_buffer_band;
			ptr_buffer_band = buffer_ptr;

			while(bands_processed < meter_entry[meter_index]->band_count)
			{
				ptr_buffer_band->packet_band_count	= htonll(band_stats_array[meter_index].band_stats[bands_processed].byte_band_count);
				ptr_buffer_band->byte_band_count	= htonll(band_stats_array[meter_index].band_stats[bands_processed].packet_band_count);
				
				ptr_buffer_band++;
				bands_processed++;
			}
			
			// update buffer pointer
			buffer_ptr = ptr_buffer_band;
			
			meter_index++;
		}
		
		return (buffer_ptr - buffer);	// return length
	}
		
	TRACE("openflow_13.c: request for meter statistics (meter id %d)", req_id);
	// Find meter entry with specified meter id
	int meter_index = 0;
	while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
	{
		if(meter_entry[meter_index]->meter_id == req_id)
		{
			TRACE("of_helper.c: meter entry found - continuing");
			break;
		}
			
		meter_index++;
	}
	if(meter_entry[meter_index] == NULL || meter_index == MAX_METER_13)
	{
		TRACE("of_helper.c: error - meter entry not found");
			
		of_error13(req, OFPET13_METER_MOD_FAILED, OFPMMFC13_UNKNOWN_METER);

		return 0;	// return length
	}
		
	// Calculate total size
	uint16_t total_size = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_meter_stats) + (meter_entry[meter_index]->band_count*sizeof(struct ofp13_meter_band_stats));
		
	// Format reply
	reply.type				= htons(OFPMP13_METER);
	reply.flags				= 0;	// Single reply
		
	// Format header
	reply.header.version	= OF_Version;
	reply.header.type		= OFPT13_MULTIPART_REPLY;
	reply.header.length		= htons(total_size);
	reply.header.xid		= req->header.xid;
		
	// Copy reply
	memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
	buffer_ptr += sizeof(struct ofp13_multipart_reply);
		
	// Format reply with specified meter statistics
	meter_stats.meter_id		= htonl(req_id);
	meter_stats.len				= htons(total_size - sizeof(struct ofp13_multipart_reply));
	
	meter_entry[meter_index]->flow_count = get_bound_flows(req_id);
	meter_stats.flow_count		= htonl(meter_entry[meter_index]->flow_count);
	
	meter_stats.packet_in_count = htonll(meter_entry[meter_index]->packet_in_count);
	meter_stats.byte_in_count	= htonll(meter_entry[meter_index]->byte_in_count);
	meter_stats.duration_sec	= htonl((sys_get_ms()-meter_entry[meter_index]->time_added)/1000);
	meter_stats.duration_nsec	= 0;	// nanosecond accuracy unsupported

		
	// Copy configuration
	memcpy(buffer_ptr, &meter_stats, sizeof(struct ofp13_meter_stats));
	buffer_ptr += sizeof(struct ofp13_meter_stats);
		
	// Format bands
	int bands_processed = 0;
	struct ofp13_meter_band_stats * ptr_buffer_band;
	ptr_buffer_band = buffer_ptr;

	while(bands_processed < meter_entry[meter_index]->band_count)
	{
		ptr_buffer_band->packet_band_count	= htonll(band_stats_array[meter_index].band_stats[bands_processed].byte_band_count);
		ptr_buffer_band->byte_band_count	= htonll(band_stats_array[meter_index].band_stats[bands_processed].packet_band_count);
			
		ptr_buffer_band++;
		bands_processed++;
	}
		
	// update buffer pointer
	buffer_ptr = ptr_buffer_band;
		
	return (buffer_ptr - buffer);	// return length
}

/*
*	Main OpenFlow Meter Configuration message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_meter_config_reply13(uint8_t *buffer, struct ofp13_multipart_request * req)
{
	struct ofp13_meter_config meter_config;
	struct ofp13_multipart_reply reply;
	struct ofp13_meter_multipart_request *meter_config_req = req->body;
	uint32_t req_id = ntohl(meter_config_req->meter_id);
	uint8_t *buffer_ptr = buffer;
	
	if(req_id == OFPM13_ALL)
	{
		TRACE("openflow_13.c: request for all meter configurations");

		/* Reply with all meter configurations */
		
		// Count the number of meters configured, and the total number of bands
		int meter_index = 0;
		uint16_t bands_counter = 0;
		while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
		{
			bands_counter += meter_entry[meter_index]->band_count;
			meter_index++;
		};
		
		TRACE("openflow_13.c: %d meters in meter table, %d bands", meter_index, (int)bands_counter);
		
		// Calculate total size - replysize + (number of meters)*configsize + (total number of bands)*bandsize
		uint16_t	total_size = sizeof(struct ofp13_multipart_reply) + (meter_index*sizeof(struct ofp13_meter_config)) + (bands_counter*sizeof(struct ofp13_meter_band_drop));
		
		// Format reply
		reply.type				= htons(OFPMP13_METER_CONFIG);
		reply.flags				= 0;	// Single reply
	
		// Format header
		reply.header.version	= OF_Version;
		reply.header.type		= OFPT13_MULTIPART_REPLY;
		reply.header.length		= htons(total_size);
		reply.header.xid		= req->header.xid;
	
		// Copy reply
		memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
		buffer_ptr += sizeof(struct ofp13_multipart_reply);

		meter_index = 0;
		// Loop & format each meter config reply
		while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
		{
			// Format reply with specified meter configuration
			meter_config.length		= htons(sizeof(struct ofp13_meter_config) + (meter_entry[meter_index]->band_count*sizeof(struct ofp13_meter_band_drop)));
			meter_config.flags		= htons(meter_entry[meter_index]->flags);
			meter_config.meter_id	= htonl(meter_entry[meter_index]->meter_id);
			
			// Copy configuration
			memcpy(buffer_ptr, &meter_config, sizeof(struct ofp13_meter_config));
			buffer_ptr += sizeof(struct ofp13_meter_config);
			
			// Format bands
			int bands_processed = 0;
			struct ofp13_meter_band_drop * ptr_band;
			ptr_band = &(meter_entry[meter_index]->bands);
			struct ofp13_meter_band_drop * ptr_buffer_band;
			ptr_buffer_band = buffer_ptr;
			
			while(bands_processed < meter_entry[meter_index]->band_count)
			{
				ptr_buffer_band->type		= htons(ptr_band->type);
				ptr_buffer_band->len		= htons(sizeof(struct ofp13_meter_band_drop));
				ptr_buffer_band->rate		= htonl(ptr_band->rate);
				ptr_buffer_band->burst_size	= htonl(ptr_band->burst_size);
				
				ptr_buffer_band++;
				ptr_band++;	// Move to next band
				bands_processed++;
			}
			
			// update buffer pointer
			buffer_ptr = ptr_buffer_band;
			
			meter_index++;
		}
		
		return (buffer_ptr - buffer);	// return length
	}
	
	TRACE("openflow_13.c: request for meter configuration (meter id %d)", req_id);
	// Find meter entry with specified meter id
	int meter_index = 0;
	while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
	{
		if(meter_entry[meter_index]->meter_id == req_id)
		{
			TRACE("of_helper.c: meter entry found - continuing");
			break;
		}
		
		meter_index++;
	}
	if(meter_entry[meter_index] == NULL || meter_index == MAX_METER_13)
	{
		TRACE("of_helper.c: error - meter entry not found");
		
		of_error13(req, OFPET13_METER_MOD_FAILED, OFPMMFC13_UNKNOWN_METER);

		return 0;	// return length
	}
	
	// Calculate total size
	uint16_t total_size = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_meter_config) + (meter_entry[meter_index]->band_count*sizeof(struct ofp13_meter_band_drop));
	
	// Format reply
	reply.type				= htons(OFPMP13_METER_CONFIG);
	reply.flags				= 0;	// Single reply
	
	// Format header
	reply.header.version	= OF_Version;
	reply.header.type		= OFPT13_MULTIPART_REPLY;
	reply.header.length		= htons(total_size);
	reply.header.xid		= req->header.xid;
	
	// Copy reply
	memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
	buffer_ptr += sizeof(struct ofp13_multipart_reply);
	
	// Format reply with specified meter configuration
	meter_config.length		= htons(total_size - sizeof(struct ofp13_multipart_reply));
	meter_config.flags		= htons(meter_entry[meter_index]->flags);
	meter_config.meter_id	= htonl(req_id);
	
	// Copy configuration
	memcpy(buffer_ptr, &meter_config, sizeof(struct ofp13_meter_config));
	buffer_ptr += sizeof(struct ofp13_meter_config);
	
	// Format bands
	int bands_processed = 0;
	struct ofp13_meter_band_drop * ptr_band;
	ptr_band = &(meter_entry[meter_index]->bands);
	struct ofp13_meter_band_drop * ptr_buffer_band;
	ptr_buffer_band = buffer_ptr;
	
	while(bands_processed < meter_entry[meter_index]->band_count)
	{
		ptr_buffer_band->type		= htons(ptr_band->type);
		ptr_buffer_band->len		= htons(sizeof(struct ofp13_meter_band_drop));
		ptr_buffer_band->rate		= htonl(ptr_band->rate);
		ptr_buffer_band->burst_size	= htonl(ptr_band->burst_size);
		
		ptr_buffer_band++;
		ptr_band++;	// Move to next band
		bands_processed++;
	}
	
	// update buffer pointer
	buffer_ptr = ptr_buffer_band;
	
	return (buffer_ptr - buffer);	// return length
}

/*
*	Main OpenFlow Meter Features message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_meter_features_reply13(uint8_t *buffer, struct ofp13_multipart_request * req)
{
	TRACE("openflow_13.c: request for meter features");
	
	struct ofp13_meter_features meter_features;
	struct ofp13_multipart_reply reply;
	uint8_t *buffer_ptr = buffer;
	
	// Format reply
	reply.type				= htons(OFPMP13_METER_FEATURES);
	reply.flags				= 0;	// Single reply
	
	// Format header
	reply.header.version	= OF_Version;
	reply.header.type		= OFPT13_MULTIPART_REPLY;
	reply.header.length		= htons(sizeof(struct ofp13_meter_features) + sizeof(struct ofp13_multipart_reply));
	reply.header.xid		= req->header.xid;
	
	// Copy reply
	memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
	buffer_ptr += sizeof(struct ofp13_multipart_reply);
	
	// Format reply with meter features
	meter_features.max_meter	= htonl(MAX_METER_13);
	meter_features.band_types	= htonl(1<<OFPMBT13_DSCP_REMARK | 1<<OFPMBT13_DROP);		// Only OFPMBT_DROP supported
	meter_features.capabilities	= htonl(OFPMF13_KBPS | OFPMF13_PKTPS);
	meter_features.max_bands	= MAX_METER_BANDS_13;
	meter_features.max_color	= 0;
	
	// Copy configuration
	
	memcpy(buffer_ptr, &meter_features, sizeof(struct ofp13_meter_features));
	buffer_ptr += sizeof(struct ofp13_meter_features);
	
	return (buffer_ptr - buffer);	// return length
}

/*
 *	OpenFlow Multi-part GROUP Description reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_group_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    struct ofp13_multipart_reply *reply;
    reply = (struct ofp13_multipart_reply *)buffer;
    struct ofp13_group_desc group_desc;
    uint8_t *buffer_ptr = buffer + sizeof(struct ofp13_multipart_reply);
    int i;
    uint16_t len = 0;

    // Build group desc and add the reply
    for(i=0;i<MAX_GROUPS;i++)
    {
        if (group_entry13[i].active == true)
        {
            group_desc.group_id = htonl(i+1);
            group_desc.type= group_entry13[i].type;
            if (group_entry13[i].bucket_id > 0)
            {
                struct ofp13_bucket *ptr_bucket;
                ptr_bucket = (struct ofp13_bucket*)action_bucket[group_entry13[i].bucket_id-1].data;
                group_desc.length = htons(sizeof(struct ofp13_group_desc) + ntohs(ptr_bucket->len));
                memcpy(buffer_ptr, &group_desc, sizeof(struct ofp13_group_desc));
                buffer_ptr += sizeof(struct ofp13_group_desc);
                memcpy(buffer_ptr, ptr_bucket, ntohs(ptr_bucket->len));
                len += sizeof(struct ofp13_group_desc) + ntohs(ptr_bucket->len);
                buffer_ptr += ntohs(ptr_bucket->len);
            } else {
                memcpy(buffer_ptr, &group_desc, sizeof(struct ofp13_group_desc));
                len += sizeof(struct ofp13_group_desc);
                buffer_ptr += sizeof(struct ofp13_group_desc);
            }
        }
    }
    len += sizeof(struct ofp13_multipart_reply);
    // Format header
    reply->header.version	= OF_Version;
    reply->header.type		= OFPT13_MULTIPART_REPLY;
    reply->header.xid		= msg->header.xid;
    reply->header.length = htons(len);
    // Format reply
    reply->type				= htons(OFPMP13_GROUP_DESC);
    reply->flags			= 0;	// Single reply
    memcpy(buffer, reply, sizeof(struct ofp13_multipart_reply));
    return len;
}

/*
 *	OpenFlow Multi-part GROUP Statistics reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_group_stats_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    struct ofp13_group_stats group_stats;
    struct ofp13_multipart_reply *reply;
    struct ofp13_bucket_counter bucket_counters;
    reply = (struct ofp13_multipart_reply *)buffer;
    uint8_t *buffer_ptr = buffer + sizeof(struct ofp13_multipart_reply);
    int i;
    uint16_t len = 0;

    
    // Build group desc and add the reply
    for(i=0;i<MAX_GROUPS;i++)
    {
        if (group_entry13[i].active == true)
        {
            group_stats.group_id = htonl(i+1);
            if (group_entry13[i].bucket_id > 0)
            {
                group_stats.byte_count = htonll(group_entry13[i].byte_count);
                group_stats.packet_count = htonll(group_entry13[i].packet_count);
                group_stats.duration_sec = htonl(((totaltime/2)-group_entry13[i].time_added));
                group_stats.ref_count = 0;
                group_stats.length = htons(sizeof(struct ofp13_group_stats) + sizeof(struct ofp13_bucket_counter));
                memcpy(buffer_ptr, &group_stats, sizeof(struct ofp13_group_stats));
                buffer_ptr += sizeof(struct ofp13_group_stats);
                bucket_counters.byte_count = htonll(action_bucket[group_entry13[i].bucket_id-1].byte_count);
                bucket_counters.packet_count = htonll(action_bucket[group_entry13[i].bucket_id-1].packet_count);
                memcpy(buffer_ptr, &bucket_counters, sizeof(struct ofp13_bucket_counter));
                len += sizeof(struct ofp13_group_stats) + sizeof(struct ofp13_bucket_counter);
                buffer_ptr += sizeof(struct ofp13_bucket_counter);
            } else {
                memcpy(buffer_ptr, &group_stats, sizeof(struct ofp13_group_stats));
                len += sizeof(struct ofp13_group_stats);
                buffer_ptr += sizeof(struct ofp13_group_stats);
            }
        }
    }
    len += sizeof(struct ofp13_multipart_reply);
    // Format header
    reply->header.version	= OF_Version;
    reply->header.type		= OFPT13_MULTIPART_REPLY;
    reply->header.xid		= msg->header.xid;
    reply->header.length = htons(len);
    // Format reply
    reply->type				= htons(OFPMP13_GROUP);
    reply->flags			= 0;	// Single reply
    memcpy(buffer, reply, sizeof(struct ofp13_multipart_reply));
    return len;
}

/*
 *	OpenFlow Multi-part GROUP Features reply message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
int multi_group_features_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
    struct ofp13_multipart_reply reply;
    struct ofp13_group_features group_features;
    uint8_t *buffer_ptr = buffer;
    
    // Format reply
    reply.type				= htons(OFPMP13_GROUP_FEATURES);
    reply.flags				= 0;	// Single reply
    
    // Format header
    reply.header.version	= OF_Version;
    reply.header.type		= OFPT13_MULTIPART_REPLY;
    reply.header.length		= htons(sizeof(struct ofp13_group_features) + sizeof(struct ofp13_multipart_reply));
    reply.header.xid		= msg->header.xid;
    
    group_features.types = htonl(1);     // Only support OFPGT_ALL for the moment
    group_features.capabilities = 0;
    group_features.max_groups[0] = htonl(MAX_GROUPS);
    group_features.max_groups[1] = 0;
    group_features.max_groups[1] = 0;
    group_features.max_groups[1] = 0;
    group_features.actions[0] = htonl((1 << OFPAT13_OUTPUT) + (1 << OFPAT13_PUSH_VLAN)+ (1 << OFPAT13_POP_VLAN));
    group_features.actions[1] = 0;
    group_features.actions[2] = 0;
    group_features.actions[3] = 0;
    
    memcpy(buffer_ptr, &reply, sizeof(struct ofp13_multipart_reply));
    buffer_ptr += sizeof(struct ofp13_multipart_reply);
    memcpy(buffer_ptr, &group_features, sizeof(struct ofp13_group_features));

    buffer_ptr += sizeof(struct ofp13_group_features);
    return (buffer_ptr - buffer);	// return length
}

/*
 *	Main OpenFlow GROUP_MOD message function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void group_mod13(struct ofp_header *msg)
{
    struct ofp13_group_mod *ptr_fm;
    ptr_fm = (struct ofp13_group_mod *) msg;
    
    switch(htons(ptr_fm->command))
    {
        case OFPGC13_ADD:
            group_add13(msg);
            break;
            
        case OFPGC13_DELETE:
            group_delete13(msg);
            break;
            
        case OFPGC13_MODIFY:
            group_modify13(msg);
            break;
    }
    return;
}

/*
 *	OpenFlow GROUP_ADD function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void group_add13(struct ofp_header *msg)
{
    int g, b;
    int bucket_len;
    uint8_t *ptr_bucket;
    struct ofp13_group_mod *ptr_gm;
    ptr_gm = (struct ofp13_group_mod *)msg;
    
    //check for existing group ID
    if (group_entry13[ntohl(ptr_gm->group_id)-1].active == true || ntohl(ptr_gm->group_id) > MAX_GROUPS || ntohl(ptr_gm->group_id) < 1)
    {
	    of_error13(msg, OFPET13_GROUP_MOD_FAILED, OFPGMFC_GROUP_EXISTS);
	    return;
    }

    group_entry13[ntohl(ptr_gm->group_id)-1].active = true;
    group_entry13[ntohl(ptr_gm->group_id)-1].type = ptr_gm->type;
    group_entry13[ntohl(ptr_gm->group_id)-1].time_added = (totaltime/2);
    // Find empty bucket
    for(b=0;b<MAX_BUCKETS;b++)
    {
        if (action_bucket[b].active == false)
        {
            TRACE("openflow_13.c: New bucket added to group %d - position %d\n", g, b);
            bucket_len = ntohs(ptr_gm->header.length) - sizeof(struct ofp13_group_mod);
            ptr_bucket = (uint8_t*)ptr_gm + sizeof(struct ofp13_group_mod);
            if (bucket_len > 64)
            {
                of_error13(msg, OFPET13_GROUP_MOD_FAILED, OFPGMFC_BAD_BUCKET);
                return;
            }
            memcpy(action_bucket[b].data, ptr_bucket, bucket_len);
            group_entry13[ntohl(ptr_gm->group_id)-1].bucket_id = b + 1;
            action_bucket[b].active = true;
            break;
        }
    }


    // TODO: add no groups and buckets available error
    return;
}

/*
 *	OpenFlow GROUP_DELETE function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void group_delete13(struct ofp_header *msg)
{
    int g;
    struct ofp13_group_mod *ptr_gm;
    ptr_gm = (struct ofp13_group_mod *)msg;

	group_entry13[htonl(ptr_gm->group_id)-1].active = false;
	action_bucket[group_entry13[htonl(ptr_gm->group_id)-1].bucket_id-1].active = false;
	// TODO: add group delete ALL
    return;
}

/*
 *	OpenFlow GROUP_MODIFY function
 *
 *	@param *msg - pointer to the OpenFlow message.
 *
 */
void group_modify13(struct ofp_header *msg)
{
    // TODO: add group modify
    return;
}


/*
*	Main OpenFlow FLOW_MOD message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_mod13(struct ofp_header *msg)
{
	struct ofp13_flow_mod * ptr_fm;
	ptr_fm = (struct ofp13_flow_mod *) msg;

	switch(ptr_fm->command)
	{
		case OFPFC13_ADD:
		flow_add13(msg);
		break;

		case OFPFC_MODIFY:
		//flow_modify13(msg);
		break;

		case OFPFC_MODIFY_STRICT:
		//flow_modify_strict13(msg);
		break;

		case OFPFC13_DELETE:
		flow_delete13(msg);
		break;

		case OFPFC13_DELETE_STRICT:
		flow_delete_strict13(msg);
		break;
	}
	return;
}

/*
*	OpenFlow FLOW_ADD function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_add13(struct ofp_header *msg)
{
	// Return an error if tables are full
	if (iLastFlow > (MAX_FLOWS_13-1))
	{
		of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
		return;
	}
	struct ofp13_flow_mod * ptr_fm;
	ptr_fm = (struct ofp13_flow_mod *) msg;
	// Tables are numbered from 0 to (MAX_TABLES-1). If higher then (MAX_TABLES-1) return bad table error
	if (ptr_fm->table_id > (MAX_TABLES-1))
	{
		of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_TABLE_ID);
		return;
	}

	// Check for an existing flow the same
	struct flows_counter flow_count_old;
	for(int q=0;q<iLastFlow;q++)
	{
		if(ofp13_oxm_match[q] == NULL)
		{
			if((memcmp(flow_match13[q]->match.oxm_fields, ptr_fm->match.oxm_fields, 4) == 0) && (flow_match13[q]->priority == ptr_fm->priority) && (flow_match13[q]->table_id == ptr_fm->table_id))
			{
				// Check for overlap flag
				if (ptr_fm->flags &  OFPFF13_CHECK_OVERLAP)
				{
					of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_OVERLAP);
					return;
				}
				// Check if we need to reset the counters
				if (ptr_fm->flags &  OFPFF13_RESET_COUNTS)
				{
					remove_flow13(q);	// remove the matching flow
				} else
				{
					TRACE("openflow_13.c: Replacing flow %d", q);
					memcpy(&flow_count_old, &flow_counters[q], sizeof(struct flows_counter));	// Copy counters from the old flow to temp location
					remove_flow13(q);	// remove the matching flow
					memcpy(&flow_counters[iLastFlow], &flow_count_old, sizeof(struct flows_counter));	// Copy counters from the temp location to the new flow
					flow_counters[iLastFlow].duration = 0;
				}
			}
		} else
		{
			if((memcmp(ofp13_oxm_match[q], ptr_fm->match.oxm_fields, ntohs(flow_match13[q]->match.length)-4) == 0) && (flow_match13[q]->priority == ptr_fm->priority) && (flow_match13[q]->table_id == ptr_fm->table_id))
			{
				if (ptr_fm->flags &  OFPFF13_CHECK_OVERLAP)
				{
					of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_OVERLAP);
					return;
				}
				// Check if we need to reset the counters
				if (ptr_fm->flags &  OFPFF13_RESET_COUNTS)
				{
					remove_flow13(q);	// remove the matching flow
				} else
				{
					TRACE("openflow_13.c: Replacing flow %d", q);
					memcpy(&flow_count_old, &flow_counters[q], sizeof(struct flows_counter));	// Copy counters from the old flow to temp location
					remove_flow13(q);	// remove the matching flow
					memcpy(&flow_counters[iLastFlow], &flow_count_old, sizeof(struct flows_counter));	// Copy counters from the temp location to the new flow
					flow_counters[iLastFlow].duration = 0;
				}
			}
		}
	}
	
	// Allocate a space to store flow mod
	flow_match13[iLastFlow] = membag_alloc(sizeof(struct ofp13_flow_mod));	
	if (flow_match13[iLastFlow] == NULL)
	{
		TRACE("openflow_13.c: Unable to allocate %d bytes of memory for flow mod", sizeof(struct ofp13_flow_mod));
		of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
		return;
	}
	TRACE("openflow_13.c: Allocating %d bytes at %p for flow mode in flow %d", sizeof(struct ofp13_flow_mod), flow_match13[iLastFlow], iLastFlow+1);
	//printf("openflow_13.c: Allocating %d bytes at %p for flow mode in flow %d\r\n", sizeof(struct ofp13_flow_mod), flow_match13[iLastFlow], iLastFlow+1);
	memcpy(flow_match13[iLastFlow], ptr_fm, sizeof(struct ofp13_flow_mod));
	
	// Allocate a space to store match fields
	if (ntohs(ptr_fm->match.length) > 4)
	{
		ofp13_oxm_match[iLastFlow] = membag_alloc(ntohs(flow_match13[iLastFlow]->match.length)-4);	
		if (ofp13_oxm_match[iLastFlow] == NULL)
		{
			TRACE("openflow_13.c: Unable to allocate %d bytes of memory for match fields", ntohs(flow_match13[iLastFlow]->match.length)-4);
			of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
			return;
		}
		TRACE("openflow_13.c: Allocating %d bytes at %p for match field in flow %d", ntohs(flow_match13[iLastFlow]->match.length)-4, ofp13_oxm_match[iLastFlow], iLastFlow+1);
		//printf("openflow_13.c: Allocating %d bytes at %p for match field in flow %d\r\n", ntohs(flow_match13[iLastFlow]->match.length)-4, ofp13_oxm_match[iLastFlow], iLastFlow+1);
		memcpy(ofp13_oxm_match[iLastFlow], ptr_fm->match.oxm_fields, ntohs(flow_match13[iLastFlow]->match.length)-4);
	} else {
		ofp13_oxm_match[iLastFlow] = NULL;
	}

	// Allocate a space to store instructions and actions
	int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
	int instruction_size = ntohs(ptr_fm->header.length) - mod_size;
	if (instruction_size > 0)
	{
		ofp13_oxm_inst[iLastFlow] = membag_alloc(instruction_size);	
		if (ofp13_oxm_inst[iLastFlow] == NULL)
		{
			TRACE("openflow_13.c: Unable to allocate %d bytes of memory for instructions", instruction_size);
			of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
			return;
		}
		TRACE("openflow_13.c: Allocating %d bytes at %p for instruction field in flow %d", instruction_size, ofp13_oxm_inst[iLastFlow], iLastFlow+1);
		uint8_t *inst_ptr = (uint8_t *)ptr_fm + mod_size;
		memcpy(ofp13_oxm_inst[iLastFlow], inst_ptr, instruction_size);
	} else {
		ofp13_oxm_inst[iLastFlow] = NULL;
	}
	ofp13_oxm_inst_size[iLastFlow] = instruction_size;
	flow_counters[iLastFlow].duration = (totaltime/2);
	flow_counters[iLastFlow].lastmatch = (totaltime/2);
	flow_counters[iLastFlow].active = true;
	iLastFlow++;
	TRACE("openflow_13.c: New flow added at %d into table %d : priority %d : cookie 0x%" PRIx64, iLastFlow+1, ptr_fm->table_id, ntohs(ptr_fm->priority), htonll(ptr_fm->cookie));
	return;
}

void flow_delete13(struct ofp_header *msg)
{
	struct ofp13_flow_mod *ptr_fm = msg;
	TRACE("openflow_13.c: Flow mod DELETE received");
	for(int q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == false)
		{
			continue;
		}
		if (ptr_fm->table_id != OFPTT_ALL && ptr_fm->table_id != flow_match13[q]->table_id)
		{
			continue;
		}

		if (ptr_fm->cookie_mask != 0 && (ptr_fm->cookie & ptr_fm->cookie_mask) != flow_match13[q]->cookie & ptr_fm->cookie_mask)
		{
			continue;
		}
		if (ptr_fm->out_port != OFPP13_ANY)
		{
			bool out_port_match = false;
			int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
			int instruction_size = ntohs(flow_match13[q]->header.length) - mod_size;
			struct ofp13_instruction *inst;
			for(inst=ofp13_oxm_inst[q]; inst<ofp13_oxm_inst[q]+instruction_size; inst+=inst->len)
			{
				if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
				{
					struct ofp13_instruction_actions *ia = inst;
					struct ofp13_action_header *action;
					for(action=ia->actions; action<inst+inst->len; action+=action->len)
					{
						if(action->type==OFPAT13_OUTPUT)
						{
							struct ofp13_action_output *output = action;
							if (output->port == ptr_fm->out_port)
							{
								out_port_match = true;
							}
						}
					}
				}
			}

			if(out_port_match==false)
			{
				continue;
			}
		}
		if (ptr_fm->out_group != OFPG13_ANY)
		{
			bool out_group_match = false;
			int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
			int instruction_size = ntohs(flow_match13[q]->header.length) - mod_size;
			struct ofp13_instruction *inst;
			for(inst=ofp13_oxm_inst[q]; inst<ofp13_oxm_inst[q]+instruction_size; inst+=inst->len)
			{
				if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
				{
					struct ofp13_instruction_actions *ia = inst;
					struct ofp13_action_header *action;
					for(action=ia->actions; action<inst+inst->len; action+=action->len)
					{
						if(action->type==OFPAT13_GROUP)
						{
							struct ofp13_action_group *group = action;
							if (group->group_id == ptr_fm->out_group)
							{
								out_group_match = true;
							}
						}
					}
				}
			}
			if(out_group_match==false)
			{
				continue;
			}
		}

		if(field_match13(ptr_fm->match.oxm_fields, ntohs(ptr_fm->match.length)-4, ofp13_oxm_match[q], ntohs(flow_match13[q]->match.length)-4) == 0)
		{
			continue;
		}

		if (ntohs(ptr_fm->flags) & OFPFF13_SEND_FLOW_REM || ntohs(flow_match13[q]->flags) &  OFPFF13_SEND_FLOW_REM) flowrem_notif13(q,OFPRR13_DELETE);
		TRACE("openflow_13.c: Flow %d removed", q+1);
		// Remove the flow entry
		remove_flow13(q);
		q--;
	}
	return;
}

/*
*	OpenFlow FLOW Delete Strict function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_delete_strict13(struct ofp_header *msg)
{
	struct ofp13_flow_mod *ptr_fm = msg;
	TRACE("openflow_13.c: Flow mod DELETE STRICT received");
	for(int q=0;q<iLastFlow;q++)
	{
		// Check if the flow is active
		if(flow_counters[q].active == false)
		{
			continue;
		}
		// Check if it is the correct flow table
		if (ptr_fm->table_id != OFPTT_ALL && ptr_fm->table_id != flow_match13[q]->table_id)
		{
			continue;
		}
		// Check if the priority is the same
		if (ptr_fm->priority != flow_match13[q]->priority)
		{
			continue;
		}
		// Check if the cookie values are the same
		if (ptr_fm->cookie_mask != 0 && (ptr_fm->cookie & ptr_fm->cookie_mask) != flow_match13[q]->cookie & ptr_fm->cookie_mask)
		{
			continue;
		}
		
		if (ptr_fm->out_port != OFPP13_ANY)
		{
			bool out_port_match = false;
			int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
			int instruction_size = ntohs(flow_match13[q]->header.length) - mod_size;
			struct ofp13_instruction *inst;
			for(inst=ofp13_oxm_inst[q]; inst<ofp13_oxm_inst[q]+instruction_size; inst+=inst->len)
			{
				if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
				{
					struct ofp13_instruction_actions *ia = inst;
					struct ofp13_action_header *action;
					for(action=ia->actions; action<inst+inst->len; action+=action->len)
					{
						if(action->type==OFPAT13_OUTPUT)
						{
							struct ofp13_action_output *output = action;
							if (output->port == ptr_fm->out_port)
							{
								out_port_match = true;
							}
						}
					}
				}
			}

			if(out_port_match == false)
			{
				continue;
			}
		}
		if (ptr_fm->out_group != OFPG13_ANY)
		{
			bool out_group_match = false;
			int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
			int instruction_size = ntohs(flow_match13[q]->header.length) - mod_size;
			struct ofp13_instruction *inst;
			for(inst=ofp13_oxm_inst[q]; inst<ofp13_oxm_inst[q]+instruction_size; inst+=inst->len)
			{
				if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
				{
					struct ofp13_instruction_actions *ia = inst;
					struct ofp13_action_header *action;
					for(action=ia->actions; action<inst+inst->len; action+=action->len)
					{
						if(action->type==OFPAT13_GROUP)
						{
							struct ofp13_action_group *group = action;
							if (group->group_id == ptr_fm->out_group)
							{
								out_group_match = true;
							}
						}
					}
				}
			}
			if(out_group_match==false)
			{
				continue;
			}
		}

		if(ofp13_oxm_match[q] == NULL)
		{
			if(memcmp(flow_match13[q]->match.oxm_fields, ptr_fm->match.oxm_fields, 4) != 0)
			{
				continue;
			}
		} else
		{
			if(memcmp(ofp13_oxm_match[q], ptr_fm->match.oxm_fields, ntohs(flow_match13[q]->match.length)-4) != 0)
			{
				continue;
			}
		}

		if (ntohs(ptr_fm->flags) & OFPFF13_SEND_FLOW_REM || ntohs(flow_match13[q]->flags) &  OFPFF13_SEND_FLOW_REM) flowrem_notif13(q,OFPRR13_DELETE);
		TRACE("openflow_13.c: Flow %d removed", q+1);
		// Remove the flow entry
		remove_flow13(q);
		q--;
	}
	return;
}

/*
*	OpenFlow PACKET_IN function
*
*	@param *buffer - pointer to the buffer containing the packet.
*	@param ul_size - size of the packet.
*	@param *buffer - port that the packet was received on.
*	@param reason - reason for the packet in.
*
*/
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint32_t port, uint8_t reason, int flow)
{
	TRACE("openflow_13.c: Packet in from packet received on port %d reason = %d (%d bytes)", port, reason, ul_size);
	uint16_t size = 0;
	struct ofp13_packet_in * pi;
	uint16_t send_size = ul_size;
	struct oxm_header13 oxm_header;
	uint32_t in_port = ntohl(port);

	if(tcp_sndbuf(tcp_pcb) < (send_size + 34)) return;

	pi = (struct ofp13_packet_in *) shared_buffer;
	pi->header.version = OF_Version;
	pi->header.type = OFPT13_PACKET_IN;
	pi->header.xid = 0;
	pi->buffer_id = -1;
	pi->reason = reason;
	pi->table_id = flow_match13[flow]->table_id;
	pi->cookie = flow_match13[flow]->cookie;

	pi->match.type = htons(OFPMT_OXM);
	pi->match.length = htons(12);
	oxm_header.oxm_class = ntohs(0x8000);
	oxm_header.oxm_field = OFPXMT_OFB_IN_PORT;
	oxm_header.oxm_len = 4;
	memcpy(shared_buffer + sizeof(struct ofp13_packet_in)-4, &oxm_header, 4);
	memcpy(shared_buffer + sizeof(struct ofp13_packet_in), &in_port, 4);
 	size = sizeof(struct ofp13_packet_in) + 10 + send_size;
	pi->header.length = HTONS(size);
	pi->total_len = HTONS(send_size);
	memcpy(shared_buffer + (size-send_size), buffer, send_size);
	sendtcp(&shared_buffer, size, 1);
	return;
}

/*
*	OpenFlow PACKET_OUT function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void packet_out13(struct ofp_header *msg)
{
	struct ofp13_packet_out * po;
	po = (struct ofp13_packet_out *) msg;
	uint32_t inPort = htonl(po->in_port);
	uint8_t *ptr = (uint8_t *) po;
	int size = ntohs(po->header.length) - ((sizeof(struct ofp13_packet_out) + ntohs(po->actions_len)));
	ptr += sizeof(struct ofp13_packet_out) + ntohs(po->actions_len);
	if (size < 0) return; // Corrupt packet!
	struct ofp13_action_header *act_hdr = po->actions;
	if (ntohs(act_hdr->type) != OFPAT13_OUTPUT) return;
	struct ofp13_action_output *act_out = act_hdr;
	uint32_t outPort = htonl(act_out->port);
	
	if (outPort == OFPP13_TABLE)
	{
		TRACE("openflow_13.c: Packet out TABLE (port %d)", inPort);
		nnOF13_tablelookup(ptr, &size, inPort);
		return;
	}
	
	if (outPort == OFPP13_FLOOD)
	{
		outPort = 7 - (1 << (inPort-1));	// Need to fix this, may also send out the Non-OpenFlow port
		} else {
		outPort = 1 << (outPort-1);
		TRACE("openflow_13.c: Packet out FLOOD (%d bytes)", size);
	}
	TRACE("openflow_13.c: Packet out port %d (%d bytes)", outPort, size);
	gmac_write(ptr, size, outPort);
	return;
}

/*
*	OpenFlow BARRIER Reply message function
*
*	@param xid - transaction ID
*
*/
void barrier13_reply(uint32_t xid)
{
	TRACE("Sent Barrier reply");
	struct ofp_header of_barrier;
	of_barrier.version= OF_Version;
	of_barrier.length = htons(sizeof(of_barrier));
	of_barrier.type   = OFPT13_BARRIER_REPLY;
	of_barrier.xid = xid;
	sendtcp(&of_barrier, sizeof(of_barrier), 0);
	return;
}

/*
*	Main OpenFlow METER_MOD message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void meter_mod13(struct ofp_header *msg)
{
	struct ofp13_meter_mod * ptr_mm;
	ptr_mm = (struct ofp13_meter_mod *) msg;
		
	switch(ntohs(ptr_mm->command))
	{
		case OFPMC13_ADD:
		meter_add13(msg);
		break;

		case OFPMC13_MODIFY:
		meter_modify13(msg);
		break;

		case OFPMC13_DELETE:
		meter_delete13(msg);
		break;
	}
	
	return;
}

/*
*	OpenFlow METER_ADD function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void meter_add13(struct ofp_header *msg)
{
	// Check if final table entry is populated
	if(meter_entry[(MAX_METER_13)-1] != NULL)
	{
		TRACE("openflow_13.c: unable to add meter - no more meters available");
		of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_METERS);
		return;
	}
	
	struct ofp13_meter_mod * ptr_mm;
	ptr_mm = (struct ofp13_meter_mod *) msg;
	
	// Check for existing meter
	int meter_index = 0;
	while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
	{
		if(ntohl(ptr_mm->meter_id) == meter_entry[meter_index]->meter_id)
		{
			TRACE("openflow_13.c: unable to add meter - meter id already in use");
			of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_METER_EXISTS);
			return;
		}
		
		meter_index++;
	}
	// meter_index now holds the next available entry in the meter table
		
	// Find number of bands
	uint16_t bands_received = ((ntohs(ptr_mm->header.length) - sizeof(struct ofp_header) - METER_PARTIAL))/sizeof(struct ofp13_meter_band_drop);	// FIX
							// Band list length is inferred from the length field in the header
	TRACE("openflow_13.c: %d bands found in meter modification message", bands_received);
	
	if(bands_received > MAX_METER_BANDS_13)
	{
		of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_BANDS);
		return;
	}
	
	// Allocate space to store meter entry
	meter_entry[meter_index] = membag_alloc(sizeof(struct meter_entry13) + (bands_received * sizeof(struct ofp13_meter_band_drop)));
	
	// Verify memory allocation
	if (meter_entry[meter_index] == NULL)
	{
		TRACE("openflow_13.c: unable to allocate %d bytes of memory for meter entry #%d", sizeof(struct meter_entry13) + (bands_received * sizeof(struct ofp13_meter_band_drop)), meter_index+1);
		of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_BANDS);
		return;
	}
	TRACE("openflow_13.c: allocating %d bytes at %p for meter entry #%d", sizeof(struct meter_entry13) + (bands_received * sizeof(struct ofp13_meter_band_drop)), meter_entry[meter_index], meter_index+1);
	
	// Copy meter configs over
	meter_entry[meter_index]->meter_id = ntohl(ptr_mm->meter_id);
	meter_entry[meter_index]->flags = ntohs(ptr_mm->flags);
	meter_entry[meter_index]->band_count = bands_received;
	
	// Initialise time added
	meter_entry[meter_index]->time_added = sys_get_ms();
	
	// Copy bands over
	if(bands_received != 0)
	{
		struct ofp13_meter_band_drop * ptr_band;
		uint16_t bands_processed = 0;
		
		// Initialise pointer to first meter band destination
		ptr_band = &(meter_entry[meter_index]->bands);
		struct ofp13_meter_band_drop * ptr_rxband;
		ptr_rxband = &(ptr_mm->bands);
		
		do 
		{
			// Copy individual band
				//memcpy((ptr_band + band_size*bands_processed), ((ptr_mm->bands) + band_size*bands_processed), PADDED_BAND_LEN);
			//ptr_band->type			= ntohs(ptr_mm->bands[bands_processed].type);
			//ptr_band->len			= ntohs(ptr_mm->bands[bands_processed].len);
			//ptr_band->rate			= ntohl(ptr_mm->bands[bands_processed].rate);
			//ptr_band->burst_size	= ntohl(ptr_mm->bands[bands_processed].burst_size);
			
			ptr_band->type			= ntohs(ptr_rxband->type);
			ptr_band->len			= ntohs(ptr_rxband->len);
			ptr_band->rate			= ntohl(ptr_rxband->rate);
			ptr_band->burst_size	= ntohl(ptr_rxband->burst_size);
			
			// Copy DSCP precedence level
			if(ptr_band->type == OFPMBT13_DSCP_REMARK)
			{
				((struct ofp13_meter_band_dscp_remark*)ptr_band)->prec_level = ((struct ofp13_meter_band_dscp_remark*)ptr_rxband)->prec_level;
			}
			
			ptr_band++;		// Move to next band storage location
			ptr_rxband++;	// Move to next received band
			bands_processed++;
			
			// ***** TODO : add error checking for band processing
			TRACE("openflow_13.c: %d of %d bands processed", bands_processed, bands_received);
			
		} while (bands_processed < bands_received);
	}
	
	iLastMeter++;	// Decrement last meter count
	
	return;
}

/*
*	OpenFlow METER_MODIFY function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void meter_modify13(struct ofp_header *msg)
{
	struct ofp13_meter_mod * ptr_mm;
	ptr_mm = (struct ofp13_meter_mod *) msg;
	uint32_t req_id = ntohl(ptr_mm->meter_id);
	
	TRACE("openflow_13.c: meter modify message (meter id %d)", req_id);
	// Find meter entry with specified meter id
	int meter_index = 0;
	while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
	{
		if(meter_entry[meter_index]->meter_id == req_id)
		{
			TRACE("of_helper.c: meter entry found - continuing");
			break;
		}
		
		meter_index++;
	}
	if(meter_entry[meter_index] == NULL || meter_index == MAX_METER_13)
	{
		TRACE("of_helper.c: error - meter entry not found");
		
		of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_UNKNOWN_METER);

		return;	// return length
	}
		
	// Find number of bands in received entry
	uint16_t bands_received = ((ntohs(ptr_mm->header.length) - sizeof(struct ofp_header) - METER_PARTIAL))/sizeof(struct ofp13_meter_band_drop);
	// Band list length is inferred from the length field in the header
	TRACE("openflow_13.c: %d bands found in meter modification message", bands_received);
		
	if(bands_received > MAX_METER_BANDS_13)
	{
		of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_BANDS);
		return;
	}
	
	// Store the top-level meter statistics
	struct meter_entry13 entry_save = {0};
	entry_save = *meter_entry[meter_index];
	
	// Free allocated memory
	membag_free(meter_entry[meter_index]);
	
	/* Delete band counters */
	// Create temporary empty structure
	struct meter_band_stats_array empty_stats_array = {0};
	// Copy over the existing structure
	band_stats_array[meter_index] = empty_stats_array;

	// Allocate space to store modified meter entry
	meter_entry[meter_index] = membag_alloc(sizeof(struct meter_entry13) + (bands_received * sizeof(struct ofp13_meter_band_drop)));
	
	// Verify memory allocation
	if (meter_entry[meter_index] == NULL)
	{
		TRACE("openflow_13.c: unable to allocate %d bytes of memory for meter entry #%d", sizeof(struct meter_entry13) + (bands_received * sizeof(struct ofp13_meter_band_drop)), meter_index+1);
		of_error13(msg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_BANDS);
		return;
	}
	TRACE("openflow_13.c: allocating %d bytes at %p for meter entry #%d", sizeof(struct meter_entry13) + (bands_received * sizeof(struct ofp13_meter_band_drop)), meter_entry[meter_index], meter_index+1);

	// Restore top-level statistics
	*meter_entry[meter_index] = entry_save;
	
	// Update modified configs
	meter_entry[meter_index]->flags = ntohs(ptr_mm->flags);
	meter_entry[meter_index]->band_count = bands_received;
	
	// Copy bands over
	if(bands_received != 0)
	{
		struct ofp13_meter_band_drop * ptr_band;
		uint16_t bands_processed = 0;
		
		// Initialise pointer to first meter band destination
		ptr_band = &(meter_entry[meter_index]->bands);
		struct ofp13_meter_band_drop * ptr_rxband;
		ptr_rxband = &(ptr_mm->bands);
		
		do
		{
			// Copy individual band
			//memcpy((ptr_band + band_size*bands_processed), ((ptr_mm->bands) + band_size*bands_processed), PADDED_BAND_LEN);
			//ptr_band->type			= ntohs(ptr_mm->bands[bands_processed].type);
			//ptr_band->len			= ntohs(ptr_mm->bands[bands_processed].len);
			//ptr_band->rate			= ntohl(ptr_mm->bands[bands_processed].rate);
			//ptr_band->burst_size	= ntohl(ptr_mm->bands[bands_processed].burst_size);
			
			ptr_band->type			= ntohs(ptr_rxband->type);
			ptr_band->len			= ntohs(ptr_rxband->len);
			ptr_band->rate			= ntohl(ptr_rxband->rate);
			ptr_band->burst_size	= ntohl(ptr_rxband->burst_size);
			
			// Copy DSCP precedence level
			if(ptr_band->type == OFPMBT13_DSCP_REMARK)
			{
				((struct ofp13_meter_band_dscp_remark*)ptr_band)->prec_level = ((struct ofp13_meter_band_dscp_remark*)ptr_rxband)->prec_level;
			}
			
			// ***** TODO : add error checking for band processing
			TRACE("openflow_13.c: %d of %d bands processed", bands_processed, bands_received);
			
			ptr_band++;		// Move to next band storage location
			ptr_rxband++;	// Move to next received band
			bands_processed++;
		} while (bands_processed < bands_received);
	}
	
	return;
}

/*
*	OpenFlow METER_DELETE function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void meter_delete13(struct ofp_header *msg)
{
	struct ofp13_meter_mod * ptr_mm;
	ptr_mm = (struct ofp13_meter_mod *) msg;
	
	// Check if all meters need to be deleted
	if(ntohl(ptr_mm->meter_id) == OFPM13_ALL)
	{
		TRACE("openflow_13.c: request to delete all meters");
		
		int meter_index = 0;
		
		// Create temporary empty structure
		struct meter_band_stats_array empty_stats_array = {0};
		
		// Loop through all meters
		while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13)
		{
			/* Delete entry */
			// Free allocated memory
			membag_free(meter_entry[meter_index]);
			// Clear the pointer
			meter_entry[meter_index] = NULL;
			
			/* Delete band counters */
			// Copy over the existing structure
			band_stats_array[meter_index] = empty_stats_array;
						
			meter_index++;
		}
		
		return;
	}
	
	TRACE("openflow_13.c: request to DELETE meter_id %d", ntohl(ptr_mm->meter_id));
	
	int meter_index = 0;
	int meter_location = -1;
	// Loop through existing meters
	while(meter_entry[meter_index] != NULL && meter_index < MAX_METER_13 && meter_location == -1)
	{
		// Compare requested meter_id with entry's meter_id
		if(ntohl(ptr_mm->meter_id) == meter_entry[meter_index]->meter_id)
		{
			// Store the index
			meter_location = meter_index;
		}
		
		meter_index++;
	}
	
	if(meter_location == -1)
	{
		TRACE("openflow_13.c: meter_id not found");
		// No error message required
		return;
	}
	
	/* Delete entry */
	// Free allocated memory
	membag_free(meter_entry[meter_location]);
	// Clear the pointer
	meter_entry[meter_location] = NULL;
	meter_index = meter_location;
	
	/* Delete band counters */
	// Create temporary empty structure
	struct meter_band_stats_array empty_stats_array = {0};
	// Copy over the existing structure
	band_stats_array[meter_index] = empty_stats_array;
	
	// Consolidate table
	if(meter_entry[meter_index+1] == NULL)
	{
		TRACE("openflow_13.c: meter table consolidation not required - no trailing entries");
	}
	else
	{
		TRACE("openflow_13.c: consolidating meter table");
		// Increment the index until the last meter entry is found
		while(meter_entry[meter_index+1] != NULL && (meter_index+1) < MAX_METER_13)
		{
			meter_index++;
		}
		meter_entry[meter_location] = meter_entry[meter_index];	// Move last entry into deleted entry location
		meter_entry[meter_index] = 0;	// Zero the moved entry
		
		/* Consolidate meter bands */
		// Copy last meter's band counters into the deleted entry's band counters
		band_stats_array[meter_location] = band_stats_array[meter_index];
		// Zero the moved band counters
		band_stats_array[meter_index] = empty_stats_array;
		
		TRACE("openflow_13.c: meter table contains %d meter entries", meter_index);
	}
	
	iLastMeter--;	// Decrement last meter count
	
	return;
}

/*
*	OpenFlow ERROR message function
*
*	@param *msg - pointer to the OpenFlow message.
*	@param - error type.
*	@param - error code.
*
*/
void of_error13(struct ofp_header *msg, uint16_t type, uint16_t code)
{
	TRACE("openflow_13.c: Sent OF error code %d", code);
	// get the size of the message, we send up to the first 64 back with the error
	int msglen = htons(msg->length);
	if (msglen > 64) msglen = 64;
	char error_buf[96];
	struct ofp_error_msg error;
	error.header.type = OFPT13_ERROR;
	error.header.version = OF_Version;
	error.header.length = htons(sizeof(struct ofp_error_msg) + msglen);
	error.header.xid = msg->xid;
	error.type = htons(type);
	error.code = htons(code);
	memcpy(error_buf, &error, sizeof(struct ofp_error_msg));
	memcpy(error_buf + sizeof(struct ofp_error_msg), msg, msglen);
	sendtcp(&error_buf, (sizeof(struct ofp_error_msg) + msglen), 1);
	return;
}

/*
*	OpenFlow FLOW Removed message function
*
*	@param flowid - flow number.
*	@param reason - the reason the flow was removed.
*
*/
void flowrem_notif13(int flowid, uint8_t reason)
{
	struct ofp13_flow_removed ofr;
	double diff;
	uint16_t match_length;
	uint16_t match_padding;
	char flow_rem[128] = {0};

	ofr.header.type = OFPT13_FLOW_REMOVED;
	ofr.header.version = OF_Version;
	// calculate the padding such that ofp_match is 32-bit aligned
	match_length = ntohs(flow_match13[flowid]->match.length);
	match_padding = ((match_length + 7)/8*8 - match_length);
	// match_length includes the total length of the ofp_match field (including header,
	// excluding padding), but sizeof(struct ofp13_flow_removed) already counted the
	// 8 bytes of sizeof(struct ofp_match)
	// => subtract the duplicate 8 bytes + length of match field + padding of match field
	ofr.header.length = htons((sizeof(struct ofp13_flow_removed) - 8) + match_length + match_padding);
	
	ofr.header.xid = 0;
	ofr.cookie = flow_match13[flowid]->cookie;
	ofr.reason = reason;
	ofr.priority = flow_match13[flowid]->priority;
	diff = (totaltime/2) - flow_counters[flowid].duration;
	ofr.duration_sec = htonl(diff);
	ofr.duration_nsec = 0;
	ofr.packet_count = htonll(flow_counters[flowid].hitCount);
	ofr.byte_count = htonll(flow_counters[flowid].bytes);
	ofr.idle_timeout = flow_match13[flowid]->idle_timeout;
	ofr.hard_timeout = flow_match13[flowid]->hard_timeout;
	ofr.table_id = flow_match13[flowid]->table_id;
	memcpy(&ofr.match, &flow_match13[flowid]->match, sizeof(struct ofp13_match));
	memcpy(flow_rem, &ofr, sizeof(struct ofp13_flow_removed));
	if (ntohs(flow_match13[flowid]->match.length) > 4) 
	{
		memcpy(flow_rem + (sizeof(struct ofp13_flow_removed)-4), ofp13_oxm_match[flowid], ntohs(flow_match13[flowid]->match.length)-4);
	}
	sendtcp(&flow_rem, htons(ofr.header.length), 1);
	TRACE("openflow_13.c: Flow removed notification sent");
	return;
}

/*
*	OpenFlow Port Status message function
*
*	@param port - port number that has changed.
*
*/
void port_status_message13(uint8_t port)
{
	char portname[8];
	uint8_t mac[] = {0x00,0x00,0x00,0x00,0x00,0x00};
	struct ofp13_port_status ofps;
	
	ofps.header.type = OFPT13_PORT_STATUS;
	ofps.header.version = OF_Version;
	ofps.header.length = htons(sizeof(struct ofp13_port_status));
	ofps.header.xid = 0;
	ofps.reason = OFPPR13_MODIFY;
	ofps.desc.port_no = htonl(port+1);
	for(int k = 0; k<6; k++)            // Generate random MAC address
	{
		int r = rand() % 255;
		memset(mac + k,r,1);
	}
	memcpy(&ofps.desc.hw_addr, mac, sizeof(mac));
	memset(ofps.desc.name, 0, OFP13_MAX_PORT_NAME_LEN);	// Zero out the name string
	sprintf(portname, "eth%d",port);
	strcpy(ofps.desc.name, portname);
	ofps.desc.config = 0;
	if (port_status[port] == 1) ofps.desc.state = htonl(OFPPS13_LIVE);
	if (port_status[port] == 0) ofps.desc.state = htonl(OFPPS13_LINK_DOWN);
	ofps.desc.curr = htonl(OFPPF13_100MB_FD + OFPPF13_COPPER);
	ofps.desc.advertised = 0;
	ofps.desc.supported = 0;
	ofps.desc.peer = 0;
	ofps.desc.curr_speed = 0;
	ofps.desc.max_speed = 0;
	sendtcp(&ofps, htons(ofps.header.length), 1);
	TRACE("openflow_13.c: Port Status change notification sent");
	return;
}
