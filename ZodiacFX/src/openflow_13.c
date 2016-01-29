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
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "lwip/tcp.h"

// Global variables
extern struct zodiac_config Zodiac_Config;
extern struct tcp_pcb *tcp_pcb;
extern int OF_Version;
extern int iLastFlow;
extern int totaltime;
extern struct ofp13_flow_mod flow_match13[MAX_FLOWS];
extern uint8_t *ofp13_oxm_match[MAX_FLOWS];
extern uint8_t *ofp13_oxm_inst[MAX_FLOWS];
extern struct flows_counter flow_counters[MAX_FLOWS];
extern struct ofp13_port_stats phys13_port_stats[4];
extern struct table_counter table_counters;
extern uint8_t port_status[4];
extern struct ofp_switch_config Switch_config;
extern uint8_t shared_buffer[2048];
extern int delay_barrier;
extern uint32_t barrier_xid;
extern int multi_pos;

// Internal functions
void features_reply13(uint32_t xid);
void of_error13(struct ofp_header *msg, uint16_t type, uint16_t code);
void set_config13(struct ofp_header * msg);
void flow_mod13(struct ofp_header *msg);
void flow_add13(struct ofp_header *msg);
void flow_delete_strict13(struct ofp_header *msg);
int multi_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_portstats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_portdesc_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_tablefeat_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason, uint16_t flow_id);
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
	uint16_t eth_prot;
	memcpy(&eth_prot, p_uc_data + 12, 2);
	uint16_t packet_size;
	memcpy(&packet_size, ul_size, 2);
	uint16_t vlantag = htons(0x8100);
			
	if (Zodiac_Config.OFEnabled == OF_ENABLED && iLastFlow == 0) // Check to if the flow table is empty
	{
		packet_in13 (p_uc_data, packet_size, port, OFPR13_NO_MATCH, 0xffff); // Packet In if there are no flows in the table
		return;
	}
	
	if (Zodiac_Config.OFEnabled == OF_ENABLED && iLastFlow > 0) // Main lookup
	{
		int i = -1;
		// Check if packet matches an existing flow
		i = flowmatch13(p_uc_data, port);
		if (i == -2) return;	// Error packet
		if (i == -1)	// No match
		{
			packet_in13 (p_uc_data, packet_size, port, OFPR13_NO_MATCH, 0xffff); // Packet In if there are no flows in the table
			return;
		}
		
		if ( i > -1)
		{
			flow_counters[i].hitCount++; // Increment flow hit count
			flow_counters[i].bytes += packet_size;
			flow_counters[i].lastmatch = totaltime; // Increment flow hit count
			table_counters.matched_count++;
			
			struct ofp13_instruction_actions *inst_actions;
			struct ofp13_action_header *act_hdr;
			struct ofp13_instruction *inst_ptr; 
			inst_ptr = (struct ofp13_instruction *) ofp13_oxm_inst[i];
			int inst_size = ntohs(inst_ptr->len);
			if(ntohs(inst_ptr->type) == OFPIT13_APPLY_ACTIONS)
			{
				int act_size = 0;
				while (act_size < (inst_size - sizeof(struct ofp13_instruction_actions)))
				{
					inst_actions  = ofp13_oxm_inst[i] + act_size;
					act_hdr = &inst_actions->actions;
					if (htons(act_hdr->type) == OFPAT13_OUTPUT)
					{
						struct ofp13_action_output *act_output = act_hdr;
						if (htonl(act_output->port) < OFPP13_MAX)
						{
							int outport = (1<< (ntohl(act_output->port)-1));
							gmac_write(p_uc_data, packet_size, outport);
						} else if (htonl(act_output->port) == OFPP13_CONTROLLER)
						{
							int pisize = ntohs(act_output->max_len);
							if (pisize > packet_size) pisize = packet_size;
							packet_in13(p_uc_data, pisize, port, OFPR_ACTION, i);
						} else if (htonl(act_output->port) == OFPP13_FLOOD)
						{
							int outport = 7 - (1<< (ntohl(act_output->port)-1));	// Need to fix this, may also send out the Non-OpenFlow port
							gmac_write(p_uc_data, packet_size, outport);
						}
					}
					if (htons(act_hdr->type) == OFPAT13_SET_FIELD)
					{
						struct ofp13_action_set_field *act_set_field = act_hdr;
						struct oxm_header13 oxm_header;
						uint16_t oxm_value16;
						uint32_t oxm_value32;
						memcpy(&oxm_header, act_set_field->field,4);
						oxm_header.oxm_field = oxm_header.oxm_field >> 1;		
						switch(oxm_header.oxm_field)
						{
							case OFPXMT_OFB_VLAN_VID:
							memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
							//uint16_t vlan_vid = (ntohs(oxm_value16) - 0x1000);
							uint16_t vlan_vid = (oxm_value16 - 0x10);
							//printf("   Set VLAN ID: %d\r\n", vlan_vid);
					
							uint16_t action_vlanid  = act_hdr;
							uint16_t pcp;
							uint16_t vlanid;
							uint16_t vlanid_mask = htons(0x0fff);
						
							if (eth_prot == vlantag)
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
							if (eth_prot == vlantag)
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
								}
							}				
							break;
						};													
					}								
					act_size += htons(act_hdr->len);
				}
			}
		}
	}
	return;
}

void of13_message(struct ofp_header *ofph, int size, int len)
{
	struct ofp13_multipart_reply *multi_req;	
	switch(ofph->type)
	{
		case OFPT13_FEATURES_REQUEST:
		features_reply13(ofph->xid);
		break;
		
		case OFPT13_SET_CONFIG:
		set_config13(ofph);
		break;

		case OFPT13_FLOW_MOD:
		flow_mod13(ofph);
		break;
				
		case OFPT13_MULTIPART_REQUEST:
		multi_req  = (struct ofp13_multipart_request *) ofph;
		if ( HTONS(multi_req->type) == OFPMP13_DESC )
		{
			multi_pos += multi_desc_reply13(&shared_buffer[multi_pos], multi_req);
		}
		
		if ( HTONS(multi_req->type) == OFPMP13_PORT_DESC )
		{
			multi_pos += multi_portdesc_reply13(&shared_buffer[multi_pos], multi_req);
		}

		if ( HTONS(multi_req->type) == OFPMP13_TABLE_FEATURES )
		{
			multi_pos += multi_tablefeat_reply13(&shared_buffer[multi_pos], multi_req);
		}
		
		if ( HTONS(multi_req->type) == 	OFPMP13_FLOW )
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
	features.n_tables = 1;		// Number of flow tables
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
			phys_port[j].state = htonl(OFPPS13_LIVE);
			if (port_status[l] == 1) phys_port[j].state = htonl(OFPPS13_LIVE);
			if (port_status[l] == 0) phys_port[j].state = htonl(OFPPS13_LINK_DOWN);
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
*	OpenFlow Multi-part TABLE Features reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_tablefeat_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	struct ofp13_multipart_reply *reply;
	struct ofp13_table_features tbl_feats;
	int len = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_table_features);
	char tablename[OFP13_MAX_TABLE_NAME_LEN];
		
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.length = htons(len);
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_TABLE_FEATURES);
	
	tbl_feats.length = htons(sizeof(struct ofp13_table_features));
	tbl_feats.table_id = 100;
	sprintf(tablename, "table_100");
	strcpy(tbl_feats.name, tablename);	
	tbl_feats.metadata_match = 0;
	tbl_feats.metadata_write = 0;
	tbl_feats.config = 0;
	tbl_feats.max_entries = htonl(MAX_FLOWS);
	memcpy(reply->body, &tbl_feats, sizeof(struct ofp13_table_features));
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
	
	if(iLastFlow > 12) iLastFlow = 12;	// Need to fix this! LWIP won't send buffers bigger then 1 packet (1460 bytes)
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
	int port = ntohs(port_req->port_no);

	if (port == OFPP_NONE)
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
			zodiac_port_stats[k].port_no = htons(k+1);
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
		memcpy(buffer[sizeof(struct ofp13_multipart_reply)], &zodiac_port_stats[0],stats_size);
	} else
	{
		stats_size = sizeof(struct ofp13_port_stats);
		len = sizeof(struct ofp13_multipart_reply) + stats_size;
		
		reply.header.version = OF_Version;
		reply.header.type = OFPT13_MULTIPART_REPLY;
		reply.header.length = htons(len);
		reply.header.xid = msg->header.xid;
		reply.type = htons(OFPMP13_PORT_STATS);
		reply.flags = 0;

		zodiac_port_stats[port].port_no = htons(port);
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
		memcpy(buffer[sizeof(struct ofp13_multipart_reply)], &zodiac_port_stats[port],stats_size);
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

	switch(ptr_fm->command)
	{
		case OFPFC13_ADD:
		flow_add13(msg);
		break;
		
		case OFPFC_MODIFY:
		//flow_modify(msg);
		break;
		
		case OFPFC_MODIFY_STRICT:
		//flow_modify_strict(msg);
		break;
		
		case OFPFC13_DELETE:
		//flow_delete13(msg);
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
	
	if (iLastFlow > (MAX_FLOWS-1))
	{
		of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
		return;
	}
	
	struct ofp13_flow_mod * ptr_fm;
	ptr_fm = (struct ofp13_flow_mod *) msg;
	memcpy(&flow_match13[iLastFlow], ptr_fm, sizeof(struct ofp13_flow_mod));
	if (htons(ptr_fm->match.length) > 4)
	{
		ofp13_oxm_match[iLastFlow] = malloc(htons(flow_match13[iLastFlow].match.length)-4);	// Allocate a space to store match fields
		memcpy(ofp13_oxm_match[iLastFlow], ptr_fm->match.oxm_fields, htons(flow_match13[iLastFlow].match.length)-4);
	} else {
		ofp13_oxm_match[iLastFlow] = NULL;
	}
	int mod_size = (sizeof(struct ofp13_flow_mod) + (htons(ptr_fm->match.length)-8));
	if (mod_size % 8 != 0) mod_size += (8-(mod_size % 8));
	int instruction_size = htons(ptr_fm->header.length) - mod_size;
	if (instruction_size > 0)
	{
		ofp13_oxm_inst[iLastFlow] = malloc(instruction_size);	// Allocate a space to store instructions and actions
		uint8_t *inst_ptr = (uint8_t *)ptr_fm + mod_size;
		memcpy(ofp13_oxm_inst[iLastFlow], inst_ptr, instruction_size);
	} else {
		ofp13_oxm_inst[iLastFlow] = NULL;
	}	
			
	flow_counters[iLastFlow].duration = totaltime;
	flow_counters[iLastFlow].lastmatch = totaltime;
	flow_counters[iLastFlow].active = true;
	iLastFlow++;
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
	
	for(q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if((memcmp(&flow_match13[q].match, &ptr_fm->match, sizeof(struct ofp13_match)) == 0) && (memcmp(&flow_match13[q].cookie, &ptr_fm->cookie,4) == 0))
			{
				if (ptr_fm->flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(q,OFPRR_DELETE);
				// Clear flow counters and actions
				memset(&flow_counters[q], 0, sizeof(struct flows_counter));
				// Copy the last flow to here to fill the gap
				memcpy(&flow_match13[q], &flow_match13[iLastFlow-1], sizeof(struct ofp13_flow_mod));
				// If there are OXM match fields move them too
				ofp13_oxm_match[q] = ofp13_oxm_match[iLastFlow-1];
				ofp13_oxm_match[iLastFlow-1] = NULL;
				memcpy(&flow_counters[q], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
				// Clear the counters and action from the last flow that was moved
				memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
				iLastFlow --;
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
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason, uint16_t flow_id)
{
	uint16_t size = 0;
	struct ofp13_packet_in * pi;	
	uint16_t send_size = ul_size;
	
	if (send_size > 128) send_size = 128;	
	if(tcp_sndbuf(tcp_pcb) < (send_size + 34)) return;

	//memset(shared_buffer, 0, size);
	pi = (struct ofp13_packet_in *) shared_buffer;
	pi->header.version = OF_Version;
	pi->header.type = OFPT13_PACKET_IN;
	pi->header.xid = 0;
	pi->buffer_id = -1;
	pi->reason = reason;

	if (reason == OFPR_ACTION && flow_id != 0xffff)	
	{
		pi->table_id = 100;
		pi->cookie = flow_match13[flow_id].cookie;
		if (ofp13_oxm_match[flow_id] != 0)
		{
			memcpy(pi->match.type, ofp13_oxm_match[flow_id], htons(flow_match13[flow_id].match.length)-4);
			size = sizeof(struct ofp13_packet_in) + (htons(flow_match13[flow_id].match.length)-4) + 2 + send_size;
		} else {
			pi->match.type = htons(OFPMT_OXM);
			pi->match.length = htons(4);
			size = sizeof(struct ofp13_packet_in) + 2 + send_size;
		}

	} else {
		pi->table_id = 100;
		pi->cookie = 0;
		pi->match.type = htons(OFPMT_OXM);
		pi->match.length = htons(4);
		size = sizeof(struct ofp13_packet_in) + 2 + send_size;
	}
	pi->header.length = HTONS(size);
	pi->total_len = HTONS(send_size);
	memcpy(shared_buffer + (size-send_size), buffer, send_size);
	sendtcp(&shared_buffer, size);
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
	uint8_t * ptr = (uint8_t *) po;
	uint16_t *iport;
	iport = ptr + 12;
	ptr += sizeof(struct ofp13_packet_out) + NTOHS(po->actions_len);
	int size = NTOHS(po->header.length) - ((sizeof(struct ofp13_packet_out) + NTOHS(po->actions_len)));
	uint16_t *eport;
	eport = ptr - 4;
	int outPort = NTOHS(*eport);
	int inPort = NTOHS(*iport);
	
	if (outPort == OFPP_FLOOD)
	{
		outPort = 7 - (1 << (inPort-1));	// Need to fix this, may also send out the Non-OpenFlow port
		} else {
		outPort = 1 << (outPort-1);
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