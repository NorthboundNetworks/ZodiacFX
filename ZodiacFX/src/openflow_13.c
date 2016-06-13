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
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "lwip/tcp.h"

#define ALIGN8(x) (x+7)/8*8

// Global variables
extern struct zodiac_config Zodiac_Config;
extern struct tcp_pcb *tcp_pcb;
extern int OF_Version;
extern int iLastFlow;
extern int totaltime;
extern struct ofp13_flow_mod flow_match13[MAX_FLOWS];
extern uint8_t *ofp13_oxm_match[MAX_FLOWS];
extern uint8_t *ofp13_oxm_inst[MAX_FLOWS];
extern uint16_t ofp13_oxm_inst_size[MAX_FLOWS];
extern struct flows_counter flow_counters[MAX_FLOWS];
extern struct ofp13_port_stats phys13_port_stats[4];
extern struct table_counter table_counters[MAX_TABLES];
extern uint8_t port_status[4];
extern struct ofp_switch_config Switch_config;
extern uint8_t shared_buffer[2048];
extern int delay_barrier;
extern uint32_t barrier_xid;
extern int multi_pos;
extern uint8_t NativePortMatrix;
extern bool trace;

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
int multi_portstats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_portdesc_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_table_reply13(uint8_t *buffer, struct ofp13_multipart_request *req);
int multi_tablefeat_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason, int flow);
void packet_out13(struct ofp_header *msg);

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
	uint16_t eth_prot = 0;
	uint8_t ip_prot = 0;
	uint16_t packet_size;
	uint16_t vlantag = htons(0x8100);
	uint16_t empty_vid = 0;
	bool isVlanTag = false;
	
	memcpy(&packet_size, ul_size, 2);	

	if (eth_prot == vlantag)
	{
		isVlanTag = true;
		memcpy(&eth_prot, p_uc_data + 16, 2);		
		if (ntohs(eth_prot) == 0x0800) 
		{
			memcpy(&ip_prot, p_uc_data + 27, 1);
		}
	} else {
		memcpy(&eth_prot, p_uc_data + 12, 2);
		if (ntohs(eth_prot) == 0x0800) 
		{
			memcpy(&ip_prot, p_uc_data + 23, 1);
		}
	}
		
				
	if (Zodiac_Config.OFEnabled == OF_ENABLED) // Main lookup
	{
		while(1)	// Loop through until we get a miss
		{
			table_counters[table_id].lookup_count++;
			int i = -1;
			// Check if packet matches an existing flow
			i = flowmatch13(p_uc_data, port, table_id);
			if (i == -2) return;	// Error packet
			if (i == -1) return;	// No match
			if ( i > -1)
			{
				if (trace == true) printf("Matched flow %d, table %d\r\n", i+1, table_id);
				flow_counters[i].hitCount++; // Increment flow hit count
				flow_counters[i].bytes += packet_size;
				flow_counters[i].lastmatch = (totaltime/2); // Increment flow hit count
				table_counters[table_id].matched_count++;
				table_counters[table_id].byte_count += packet_size;
				
				// If there are no instructions then it's a DROP so just return
				if(ofp13_oxm_inst[i] == NULL) return;
				
				// Process Instructions
				struct ofp13_instruction_actions *inst_actions;
				struct ofp13_action_header *act_hdr;
				struct ofp13_instruction *inst_ptr; 
				inst_ptr = (struct ofp13_instruction *) ofp13_oxm_inst[i];
				int inst_size = ntohs(inst_ptr->len);
				
				if(inst_size == 0 || inst_size > 64)
				{
					remove_flow13(i);
					return;
				}

				if(ntohs(inst_ptr->type) == OFPIT13_APPLY_ACTIONS)
				{
					int act_size = 0;
					while (act_size < (inst_size - sizeof(struct ofp13_instruction_actions)))
					{
						inst_actions  = ofp13_oxm_inst[i] + act_size;
						act_hdr = &inst_actions->actions;
						// Output Action
						if (htons(act_hdr->type) == OFPAT13_OUTPUT)
						{
							struct ofp13_action_output *act_output = act_hdr;
							if (htonl(act_output->port) < OFPP13_MAX)
							{
								int outport = (1<< (ntohl(act_output->port)-1));
								if (trace == true)printf("Output to port %d (%d bytes)\r\n", ntohl(act_output->port), packet_size);
								gmac_write(p_uc_data, packet_size, outport);
							} else if (htonl(act_output->port) == OFPP13_CONTROLLER)
							{
								int pisize = ntohs(act_output->max_len);
								if (pisize > packet_size) pisize = packet_size;
								if (trace == true)printf("Output to controller (%d bytes)\r\n", packet_size);
								packet_in13(p_uc_data, pisize, port, OFPR_ACTION, i);
							} else if (htonl(act_output->port) == OFPP13_FLOOD || htonl(act_output->port) == OFPP13_ALL)
							{
								int outport = (15 - NativePortMatrix) - (1<<(port-1));
								if (trace == true && htonl(act_output->port) == OFPP13_FLOOD) printf("Output to FLOOD (%d bytes)\r\n", packet_size);
								if (trace == true && htonl(act_output->port) == OFPP13_ALL ) printf("Output to ALL (%d bytes)\r\n", packet_size);
								gmac_write(p_uc_data, packet_size, outport);
							}
						}
						
						// Push a VLAN tag
						if (htons(act_hdr->type) == OFPAT13_PUSH_VLAN && isVlanTag != true)
						{	
							if (trace == true)printf("Push VLAN\r\n");					
							memmove(p_uc_data + 16, p_uc_data + 12, packet_size - 12);
							memcpy(p_uc_data + 12, &vlantag,2);
							memcpy(p_uc_data + 14, &empty_vid, 2);
							packet_size += 4;
							memcpy(ul_size, &packet_size, 2);
							isVlanTag = true;
						}

						// Pop a VLAN tag
						if (htons(act_hdr->type) == OFPAT13_POP_VLAN && isVlanTag == true)
						{
							if (trace == true)printf("Pop VLAN\r\n");
							memmove(p_uc_data + 12, p_uc_data + 16, packet_size - 16);
							packet_size -= 4;
							memcpy(ul_size, &packet_size, 2);
							memcpy(eth_prot, p_uc_data + 12, 2);
							isVlanTag = false; 
						}
												
						// Set Field Action
						if (htons(act_hdr->type) == OFPAT13_SET_FIELD)
						{
							struct ofp13_action_set_field *act_set_field = act_hdr;
							struct oxm_header13 oxm_header;
							uint8_t oxm_value8;
							uint16_t oxm_value16;
							uint32_t oxm_value32;
							memcpy(&oxm_header, act_set_field->field,4);
							oxm_header.oxm_field = oxm_header.oxm_field >> 1;		
							switch(oxm_header.oxm_field)
							{
								// Set VLAN ID
								case OFPXMT_OFB_VLAN_VID:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								uint16_t vlan_vid = (oxm_value16 - 0x10);
								uint16_t action_vlanid  = act_hdr;
								uint16_t pcp;
								uint16_t vlanid;
								uint16_t vlanid_mask = htons(0x0fff);
						
								if (isVlanTag == true)
								{
									memcpy(pcp, p_uc_data + 14, 2);
								} else {
									pcp = 0;
								}
								if (vlan_vid == 0xffff)
								{
									vlanid = pcp & ~vlanid_mask;
								} else {
										vlanid = (vlan_vid & vlanid_mask) | (pcp & ~vlanid_mask);
								}						
								// Does the packet have a VLAN header?
								if (isVlanTag == true)
								{
									if (vlan_vid == 0)	// If the packet has a tag but the action is to set it to 0 then remove it
									{
										memmove(p_uc_data + 12, p_uc_data + 16, packet_size - 16);
										packet_size -= 4;
										memcpy(ul_size, &packet_size, 2);
									} else {
										memcpy(p_uc_data + 14, &vlanid, 2);
									}
								} else {
									if (vlan_vid > 0)		// Only add the tag if the VLAN ID is greater then 0
									{
										memmove(p_uc_data + 16, p_uc_data + 12, packet_size - 12);
										memcpy(p_uc_data + 12, &vlantag,2);
										memcpy(p_uc_data + 14, &vlanid, 2);
										packet_size += 4;
										memcpy(ul_size, &packet_size, 2);
										if (trace == true) printf("Set VLAN ID to %d\r\n", vlanid);
										isVlanTag = true;
									}
								}				
								break;
								// Set Source Ethernet Address
								case OFPXMT_OFB_ETH_SRC:
								memcpy(p_uc_data + 6,act_set_field->field + sizeof(struct oxm_header13), 6);							
								break;
								// Set Destination Ethernet Address
								case OFPXMT_OFB_ETH_DST:
								memcpy(p_uc_data,act_set_field->field + sizeof(struct oxm_header13), 6);
								break;

								// Set Ether Type
								case OFPXMT_OFB_ETH_TYPE:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								if (isVlanTag == true)	// Add 4 bytes to the offset
								{
									memcpy(p_uc_data + 16, &oxm_value16, 2);
								} else {
									memcpy(p_uc_data + 12, &oxm_value16, 2);
								}								
								break;
																
								// Set IP protocol
								case OFPXMT_OFB_IP_PROTO:
								memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
								if (isVlanTag == true)	// Add 4 bytes to the offset
								{
									memcpy(p_uc_data + 27, &oxm_value16, 2);
									set_ip_checksum(p_uc_data, packet_size, 18);
								} else {
									memcpy(p_uc_data + 23, &oxm_value16, 2);
									set_ip_checksum(p_uc_data, packet_size, 14);
								}								
								break;
								
								// Set Source IP Address
								case OFPXMT_OFB_IPV4_SRC:
								if (eth_prot == 0x08)	// Only set the field if it is an IPv4 packet
								{
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 30, act_set_field->field + sizeof(struct oxm_header13), 4);
										set_ip_checksum(p_uc_data, packet_size, 18);
									} else {
										memcpy(p_uc_data + 26, act_set_field->field + sizeof(struct oxm_header13), 4);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}
								break;
								
								// Set Destination IP Address
								case OFPXMT_OFB_IPV4_DST:
								if (eth_prot == 0x08)	// Only set the field if it is an IPv4 packet
								{
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 34, act_set_field->field + sizeof(struct oxm_header13), 4);
										set_ip_checksum(p_uc_data, packet_size, 18);
									} else {
										memcpy(p_uc_data + 30, act_set_field->field + sizeof(struct oxm_header13), 4);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}
								break;
								
								// Set Source TCP port
								case OFPXMT_OFB_TCP_SRC:
								if (eth_prot == 0x08)	// Only set the field if it is an IPv4 packet
								{
									memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 38, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 18);
									} else {
										memcpy(p_uc_data + 34, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set Destination TCP port
								case OFPXMT_OFB_TCP_DST:
								if (eth_prot == 0x08)	// Only set the field if it is an IPv4 packet
								{
									memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 40, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 36, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set Source UDP port
								case OFPXMT_OFB_UDP_SRC:
								if (eth_prot == 0x08)	// Only set the field if it is an IPv4 packet
								{
									memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 38, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 34, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set Destination UDP port
								case OFPXMT_OFB_UDP_DST:
								if (eth_prot == 0x08)	// Only set the field if it is an IPv4 packet
								{
									memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 40, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 36, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set ICMP type
								case OFPXMT_OFB_ICMPV4_TYPE:
								if (eth_prot == 0x08 && ip_prot == 1)	// Only set the field if it is a ICMP packet
								{
									memcpy(&oxm_value8, act_set_field->field + sizeof(struct oxm_header13), 1);
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 38, &oxm_value8, 1);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 34, &oxm_value8, 1);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set ICMP code
								case OFPXMT_OFB_ICMPV4_CODE:
								if (eth_prot == 0x08 && ip_prot == 1)	// Only set the field if it is a ICMP packet
								{
									memcpy(&oxm_value8, act_set_field->field + sizeof(struct oxm_header13), 1);
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 39, &oxm_value8, 1);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 35, &oxm_value8, 1);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}									
								break;
								
								// Set ARP opcode
								case OFPXMT_OFB_ARP_OP:
								if (eth_prot == 0x0608)	// Only set the field if it is a ARP packet
								{
									memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 24, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 20, &oxm_value16, 2);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set ARP source IP address
								case OFPXMT_OFB_ARP_SPA:
								if (eth_prot == 0x0608)	// Only set the field if it is an IPv4 packet
								{
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 32, act_set_field->field + sizeof(struct oxm_header13), 4);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 28, act_set_field->field + sizeof(struct oxm_header13), 4);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set ARP target IP address
								case OFPXMT_OFB_ARP_TPA:
								if (eth_prot == 0x0608)	// Only set the field if it is an IPv4 packet
								{
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 42, act_set_field->field + sizeof(struct oxm_header13), 4);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 38, act_set_field->field + sizeof(struct oxm_header13), 4);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set ARP source hardware address
								case OFPXMT_OFB_ARP_SHA:
								if (eth_prot == 0x0608)	// Only set the field if it is an IPv4 packet
								{
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 26, act_set_field->field + sizeof(struct oxm_header13), 6);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 22, act_set_field->field + sizeof(struct oxm_header13), 6);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;
								
								// Set ARP target hardware address
								case OFPXMT_OFB_ARP_THA:
								if (eth_prot == 0x0608)	// Only set the field if it is an IPv4 packet
								{
									if (isVlanTag == true)	// Add 4 bytes to the offset
									{
										memcpy(p_uc_data + 36, act_set_field->field + sizeof(struct oxm_header13), 6);
										set_ip_checksum(p_uc_data, packet_size, 18);
										} else {
										memcpy(p_uc_data + 32, act_set_field->field + sizeof(struct oxm_header13), 6);
										set_ip_checksum(p_uc_data, packet_size, 14);
									}
								}								
								break;																																	
							};													
						}								
						act_size += htons(act_hdr->len);
					}
					
					if (ofp13_oxm_inst_size[i] > inst_size)
					{
						uint8_t *nxt_inst;
						nxt_inst = ofp13_oxm_inst[i] + inst_size;
						inst_ptr = (struct ofp13_instruction *) nxt_inst;
						inst_size = ntohs(inst_ptr->len);
					} else return;
				}
				
				if(ntohs(inst_ptr->type) == OFPIT13_GOTO_TABLE)
				{
					struct ofp13_instruction_goto_table *inst_goto_ptr;
					inst_goto_ptr = (struct ofp13_instruction_goto_table *) inst_ptr;
					if(table_id == inst_goto_ptr->table_id) return;		// Stop a goto instruction that goes to the same table as it would create a loop
					table_id = inst_goto_ptr->table_id;
					if (trace == true)printf("Goto table %d\r\n", table_id);
				}
			}
		}
	}
	return;
}

void of13_message(struct ofp_header *ofph, int size, int len)
{
	struct ofp13_multipart_reply *multi_req;
	if (trace == true) printf("%u: OpenFlow message received type = %d\r\n", htonl(ofph->xid), ofph->type);	
	switch(ofph->type)
	{
		case OFPT13_FEATURES_REQUEST:
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
				
		case OFPT13_MULTIPART_REQUEST:
		multi_req  = (struct ofp13_multipart_request *) ofph;
		if ( ntohs(multi_req->type) == OFPMP13_DESC )
		{
			multi_pos += multi_desc_reply13(&shared_buffer[multi_pos], multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_PORT_STATS )
		{
			multi_pos += multi_portstats_reply13(&shared_buffer[multi_pos], multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_PORT_DESC )
		{
			multi_pos += multi_portdesc_reply13(&shared_buffer[multi_pos], multi_req);
		}

		if ( htons(multi_req->type) == OFPMP13_TABLE_FEATURES )
		{
			multi_pos += multi_tablefeat_reply13(&shared_buffer[multi_pos], multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_TABLE )
		{
			multi_pos += multi_table_reply13(&shared_buffer[multi_pos], multi_req);
		}

		if ( ntohs(multi_req->type) == 	OFPMP13_FLOW )
		{
			multi_pos += multi_flow_reply13(&shared_buffer[multi_pos], multi_req);
		}		

		break;

		case OFPT10_PACKET_OUT:
		packet_out13(ofph);
		break;
				
		case OFPT13_BARRIER_REQUEST:
		if (size == len) {
			barrier13_reply(ofph->xid);
			delay_barrier = 0;
			} else {
			barrier_xid = ofph->xid;
			delay_barrier = 1;
		}
		break;
	};
	
	if (size == len)
	{
		sendtcp(&shared_buffer, multi_pos);
	}
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
	int numofports = 0;
	for(int n=0;n<4;n++)
	{
		if(Zodiac_Config.of_port[n]==1)numofports++;
	}
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
	features.capabilities = htonl(OFPC13_FLOW_STATS + OFPC13_TABLE_STATS + OFPC13_PORT_STATS);	// Switch Capabilities
	features.auxiliary_id = 0;	// Primary connection

	memcpy(&buf, &features, sizeof(struct ofp13_switch_features));
	sendtcp(&buf, bufsize);
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
	sendtcp(&cfg_reply, sizeof(cfg_reply));
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
	sendtcp(&role_request, sizeof(struct ofp13_role_request));
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
	static struct ofp13_desc zodiac_desc = {
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
*	OpenFlow Multi-part PORT Description reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_portdesc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	int numofports = 0;
	for(int n=0;n<4;n++)
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
	
	for(int l = 0; l< 4; l++)
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
	int len = offsetof(struct ofp13_multipart_reply, body) + sizeof(struct ofp13_table_stats);
	struct ofp13_multipart_reply *reply = buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.length = htons(len);
	reply->header.xid = msg->header.xid;
	reply->type = htons(OFPMP13_TABLE);
	reply->flags = 0;
	struct ofp13_table_stats *stats = reply->body;
	stats->table_id = 0;
	uint32_t active = 0;
	for(int i=0; i<iLastFlow; i++) {
		if (flow_counters[i].active == false){
			active++;
		}
	}
	stats->active_count = htonl(active);
	stats->matched_count = htonll(table_counters[0].matched_count);		// !!Need to add multi-table response!!
	stats->lookup_count = htonll(table_counters[0].lookup_count);
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
	tbl_feats.max_entries = htonl(MAX_FLOWS);
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
*	OpenFlow Multi-part FLOW reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	char statsbuffer[2048];
	struct ofp13_multipart_reply *reply;
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_FLOW);	
	int len = flow_stats_msg13(&statsbuffer, 0, iLastFlow);
	memcpy(reply->body, &statsbuffer, len);
	len += 	sizeof(struct ofp13_multipart_reply);
	reply->header.length = htons(len);		

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
	struct ofp13_port_stats zodiac_port_stats[3];
	struct ofp13_multipart_reply reply;
	struct ofp13_port_stats_request *port_req = msg->body;
	int stats_size = 0;
	int k, len;
	uint32_t port = ntohl(port_req->port_no);

	if (port == OFPP13_ANY)
	{
		stats_size = (sizeof(struct ofp13_port_stats) * 3);	// Assumes 3 ports
		len = sizeof(struct ofp13_multipart_reply) + stats_size;
		
		reply.header.version = OF_Version;
		reply.header.type = OFPT13_MULTIPART_REPLY;
		reply.header.length = htons(len);
		reply.header.xid = msg->header.xid;
		reply.type = htons(OFPMP13_PORT_STATS);
		reply.flags = 0;
		
		for(k=0; k<3;k++)
		{
			zodiac_port_stats[k].port_no = htonl(k+1);
			zodiac_port_stats[k].rx_packets = htonll(phys13_port_stats[k].rx_packets);
			zodiac_port_stats[k].tx_packets = htonll(phys13_port_stats[k].tx_packets);
			zodiac_port_stats[k].rx_bytes = htonll(phys13_port_stats[k].rx_bytes);
			zodiac_port_stats[k].tx_bytes = htonll(phys13_port_stats[k].tx_bytes);
			zodiac_port_stats[k].rx_crc_err = htonll(phys13_port_stats[k].rx_crc_err);
			zodiac_port_stats[k].rx_dropped = htonll(phys13_port_stats[k].rx_dropped);
			zodiac_port_stats[k].tx_dropped = htonll(phys13_port_stats[k].tx_dropped);
			zodiac_port_stats[k].rx_frame_err = 0;
			zodiac_port_stats[k].rx_over_err = 0;
			zodiac_port_stats[k].tx_errors = 0;
			zodiac_port_stats[k].rx_errors = 0;
			zodiac_port_stats[k].collisions = 0;
			
		}
		memcpy(buffer, &reply, sizeof(struct ofp13_multipart_reply));
		memcpy(buffer+sizeof(struct ofp13_multipart_reply), &zodiac_port_stats[0], stats_size);
	} else if (port <= OFPP13_MAX) {
		stats_size = sizeof(struct ofp13_port_stats);
		len = sizeof(struct ofp13_multipart_reply) + stats_size;
		
		reply.header.version = OF_Version;
		reply.header.type = OFPT13_MULTIPART_REPLY;
		reply.header.length = htons(len);
		reply.header.xid = msg->header.xid;
		reply.type = htons(OFPMP13_PORT_STATS);
		reply.flags = 0;

		zodiac_port_stats[port].port_no = htonl(port);
		zodiac_port_stats[port].rx_packets = htonll(phys13_port_stats[port-1].rx_packets);
		zodiac_port_stats[port].tx_packets = htonll(phys13_port_stats[port-1].tx_packets);
		zodiac_port_stats[port].rx_bytes = htonll(phys13_port_stats[port-1].rx_bytes);
		zodiac_port_stats[port].tx_bytes = htonll(phys13_port_stats[port-1].tx_bytes);
		zodiac_port_stats[port].rx_crc_err = htonll(phys13_port_stats[port-1].rx_crc_err);
		zodiac_port_stats[port].rx_dropped = htonll(phys13_port_stats[port-1].rx_dropped);
		zodiac_port_stats[port].tx_dropped = htonll(phys13_port_stats[port-1].tx_dropped);
		zodiac_port_stats[port].rx_frame_err = 0;
		zodiac_port_stats[port].rx_over_err = 0;
		zodiac_port_stats[port].tx_errors = 0;
		zodiac_port_stats[port].rx_errors = 0;
		zodiac_port_stats[port].collisions = 0;

		memcpy(buffer, &reply, sizeof(struct ofp13_multipart_reply));
		memcpy(buffer+sizeof(struct ofp13_multipart_reply), &zodiac_port_stats[port], stats_size);
	}
	return len;
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
// 	if (ptr_fm->match.type != 0x100)
// 	{
// 		of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
// 		return;
// 	}

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
	if (iLastFlow > (MAX_FLOWS-1))
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
			if((memcmp(&flow_match13[q].match.oxm_fields, ptr_fm->match.oxm_fields, 4) == 0) && (flow_match13[q].priority == ptr_fm->priority) && (flow_match13[q].table_id == ptr_fm->table_id))
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
					if (trace == true) printf("Replacing flow %d\r\n", q);
					memcpy(&flow_count_old, &flow_counters[q], sizeof(struct flows_counter));	// Copy counters from the old flow to temp location
					remove_flow13(q);	// remove the matching flow
					memcpy(&flow_counters[iLastFlow], &flow_count_old, sizeof(struct flows_counter));	// Copy counters from the temp location to the new flow
					flow_counters[iLastFlow].duration = 0;
				}
			}
		} else
		{
			if((memcmp(ofp13_oxm_match[q], ptr_fm->match.oxm_fields, ntohs(flow_match13[q].match.length)-4) == 0) && (flow_match13[q].priority == ptr_fm->priority) && (flow_match13[q].table_id == ptr_fm->table_id))
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
					if (trace == true) printf("Replacing flow %d\r\n", q);
					memcpy(&flow_count_old, &flow_counters[q], sizeof(struct flows_counter));	// Copy counters from the old flow to temp location
					remove_flow13(q);	// remove the matching flow
					memcpy(&flow_counters[iLastFlow], &flow_count_old, sizeof(struct flows_counter));	// Copy counters from the temp location to the new flow
					flow_counters[iLastFlow].duration = 0;
				}
			}	
		} 
	}
	if (trace == true) printf("New flow added at %d into table %d : priority %d : cookie 0x%" PRIx64 "\r\n", iLastFlow+1, ptr_fm->table_id, ntohs(ptr_fm->priority), htonll(ptr_fm->cookie));
	
	memcpy(&flow_match13[iLastFlow], ptr_fm, sizeof(struct ofp13_flow_mod));
	if (ntohs(ptr_fm->match.length) > 4)
	{
		ofp13_oxm_match[iLastFlow] = membag_alloc(ntohs(flow_match13[iLastFlow].match.length)-4);	// Allocate a space to store match fields
		if (ofp13_oxm_match[iLastFlow] == NULL) 
		{
			if (trace == true) printf("Unable to allocate %d bytes of memory for match fields\r\n", ntohs(flow_match13[iLastFlow].match.length)-4);
			of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
			return;
		}
		memcpy(ofp13_oxm_match[iLastFlow], ptr_fm->match.oxm_fields, ntohs(flow_match13[iLastFlow].match.length)-4);
	} else {
		ofp13_oxm_match[iLastFlow] = NULL;
	}
	
	int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
	int instruction_size = ntohs(ptr_fm->header.length) - mod_size;
	if (instruction_size > 0)
	{
		ofp13_oxm_inst[iLastFlow] = membag_alloc(instruction_size);	// Allocate a space to store instructions and actions
		if (ofp13_oxm_inst[iLastFlow] == NULL)
		{
			if (trace == true) printf("Unable to allocate %d bytes of memory for instructions\r\n", instruction_size);
			of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
			return;
		}
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
	return;
}

void flow_delete13(struct ofp_header *msg)
{
	struct ofp13_flow_mod *ptr_fm = msg;
	if (trace == true) printf("Flow mod DELETE received\r\n");
	for(int q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if (ptr_fm->table_id != OFPTT_ALL && ptr_fm->table_id != flow_match13[q].table_id)
			{
				continue;
			}
			
			if (ptr_fm->cookie_mask != 0 && ptr_fm->cookie != flow_match13[q].cookie & ptr_fm->cookie_mask)
			{
				continue;
			}
			if (ptr_fm->out_port != OFPP13_ANY)
			{
				bool out_port_match = false;
				int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
				int instruction_size = ntohs(flow_match13[q].header.length) - mod_size;
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
				
				if (ptr_fm->out_group != OFPG13_ANY)
				{
					bool out_group_match = false;
					int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
					int instruction_size = ntohs(flow_match13[q].header.length) - mod_size;
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
						if(out_group_match==false)
						{
							continue;
						}
						
						if(field_match13(ofp13_oxm_match[q], ntohs(flow_match13[q].match.length)-4, ptr_fm->match.oxm_fields, ntohs(ptr_fm->match.length)-4) == 0)
						{
								continue;
						}
						
						if (ptr_fm->flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(q,OFPRR_DELETE);
						if (trace == true) printf("Flow %d removed\r\n", q+1);
						// Remove the flow entry
						remove_flow13(q);
						q--;
					}
				}
			}
		}
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
	struct ofp13_flow_mod * ptr_fm;
	ptr_fm = (struct ofp13_flow_mod *) msg;
	int q;
	if (trace == true) printf("Flow mod DELETE STRICT received\r\n");
	// Look for flows with the exact match fields, cookie value and table id
	for(q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if((memcmp(&flow_match13[q].match, &ptr_fm->match, sizeof(struct ofp13_match)) == 0) && (memcmp(&flow_match13[q].cookie, &ptr_fm->cookie,8) == 0) && (flow_match13[q].priority == ptr_fm->priority) && (flow_match13[q].table_id == ptr_fm->table_id))
			{
				if (ptr_fm->flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(q,OFPRR_DELETE);
				if (trace == true) printf("Delete strict, removing flow %d\r\n", q+1);
				remove_flow13(q);
				q--;
			}
		}
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
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason, int flow)
{
	if (trace == true) printf("Packet in from packet received on port %d reason = %d (%d bytes)\r\n", port, reason, ul_size);
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
	pi->table_id = flow_match13[flow].table_id;
	pi->cookie = flow_match13[flow].cookie;

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
	sendtcp(&shared_buffer, size);
	tcp_output(tcp_pcb);
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
	uint32_t outPort;
	struct ofp13_packet_out * po;
	po = (struct ofp13_packet_out *) msg;
	uint32_t inPort = htonl(po->in_port);
	uint8_t *ptr = (uint8_t *) po;
	int size = ntohs(po->header.length) - ((sizeof(struct ofp13_packet_out) + ntohs(po->actions_len)));	
	ptr += sizeof(struct ofp13_packet_out) + ntohs(po->actions_len);
	if (size < 0) return; // Corrupt packet!
	struct ofp13_action_header *act_hdr = po->actions;
	if (ntohs(act_hdr->type) == OFPAT13_OUTPUT)	
	{
		struct ofp13_action_output *act_out = act_hdr;
		outPort = htonl(act_out->port);
		if (trace == true) printf("Packet out port %d (%d bytes)\r\n", outPort, size);
	}
	
	if (outPort == OFPP13_FLOOD)
	{
		outPort = 7 - (1 << (inPort-1));	// Need to fix this, may also send out the Non-OpenFlow port
		} else {
		outPort = 1 << (outPort-1);
		if (trace == true) printf("Packet out FLOOD (%d bytes)\r\n", size);
	}
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
	if (trace == true) printf("Sent Barrier reply\r\n");
	struct ofp_header of_barrier;
	of_barrier.version= OF_Version;
	of_barrier.length = htons(sizeof(of_barrier));
	of_barrier.type   = OFPT13_BARRIER_REPLY;
	of_barrier.xid = xid;
	sendtcp(&of_barrier, sizeof(of_barrier));
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
	if (trace == true) printf("Sent OF error code %d\r\n", code);
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
	sendtcp(&error_buf, (sizeof(struct ofp_error_msg) + msglen));
	return;
}