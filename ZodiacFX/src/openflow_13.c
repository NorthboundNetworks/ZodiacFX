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
extern struct flows_counter flow_counters[MAX_FLOWS];
extern struct ofp13_port_stats phys13_port_stats[4];
extern struct table_counter table_counters;
extern uint8_t port_status[4];
extern struct ofp_switch_config Switch_config;
extern uint8_t shared_buffer[2048];
extern int delay_barrier;
extern uint32_t barrier_xid;
extern int multi_pos;

struct ofp13_flow_mod flow_match13[MAX_FLOWS];
char *ofp13_oxm_match[MAX_FLOWS];
char *ofp13_oxm_inst[MAX_FLOWS];

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
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason);
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

void nnOF13_tablelookup(char *p_uc_data, uint32_t *ul_size, int port)
{
	uint16_t eth_prot;
	memcpy(&eth_prot, p_uc_data + 12, 2);
	uint16_t packet_size;
	memcpy(&packet_size, ul_size, 2);
	uint16_t vlantag = htons(0x8100);
				
	if (Zodiac_Config.OFEnabled == OF_ENABLED) // Main lookup
	{
		table_counters.lookup_count++;
		
		int i = -1;
		// Check if packet matches an existing flow
		i = flowmatch13(p_uc_data, port);
		if (i == -2) return;	// Error packet
		if (i == -1) return;	// No match
		
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
							packet_in13(p_uc_data, pisize, port, OFPR_ACTION);
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
							case OFPXMT13_OFB_VLAN_VID:
							memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
							uint16_t vlan_vid = (oxm_value16 - 0x10);
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
	struct ofp13_multipart_request *multi_req;	
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
	// XXX: no multi table support for now
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
	stats->matched_count = htonll(table_counters.matched_count);
	stats->lookup_count = htonll(table_counters.lookup_count);
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
	
	tbl_feats.table_id = 100;
	sprintf(tablename, "table_100");
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
 	inst_prop.type = htons(OFPTFPT13_INSTRUCTIONS);
 	inst_prop.length = htons(8);
 	inst.type = htons(OFPIT13_APPLY_ACTIONS);
 	inst.len = htons(4);
	memcpy(buffer + (len-(prop_size)), &inst_prop, 4);
	memcpy(buffer + (len-(prop_size-4)), &inst, 4);	 
	// Next Table Property
	inst_prop.type = htons(OFPTFPT13_NEXT_TABLES);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-8)), &inst_prop, 4);
	// Write Actions Property
	inst_prop.type = htons(OFPTFPT13_WRITE_ACTIONS);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-16)), &inst_prop, 4);
	// Apply Actions Property
	inst_prop.type = htons(OFPTFPT13_APPLY_ACTIONS);
	inst_prop.length = htons(8);
 	inst.type = htons(OFPAT13_OUTPUT);
 	inst.len = htons(4);
	memcpy(buffer + (len-(prop_size-24)), &inst_prop, 4);
	memcpy(buffer + (len-(prop_size-28)), &inst, 4);	
	// Match Property
	inst_prop.type = htons(OFPTFPT13_MATCH);
	inst_prop.length = htons(52);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-32)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IN_PORT << 1;		
	memcpy(buffer + (len-(prop_size-36)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_ETH_DST << 1;
	memcpy(buffer + (len-(prop_size-40)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_ETH_SRC << 1;
	memcpy(buffer + (len-(prop_size-44)), &oxm_header, 4);	
	oxm_header.oxm_field = OFPXMT13_OFB_ETH_TYPE << 1;
	memcpy(buffer + (len-(prop_size-48)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_VLAN_VID << 1;
	memcpy(buffer + (len-(prop_size-52)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IP_PROTO << 1;
	memcpy(buffer + (len-(prop_size-56)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IPV4_SRC << 1;
	memcpy(buffer + (len-(prop_size-60)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IPV4_DST << 1;
	memcpy(buffer + (len-(prop_size-64)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_TCP_SRC << 1;
	memcpy(buffer + (len-(prop_size-68)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_TCP_DST << 1;
	memcpy(buffer + (len-(prop_size-72)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_UDP_SRC << 1;
	memcpy(buffer + (len-(prop_size-76)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_UDP_DST << 1;
	memcpy(buffer + (len-(prop_size-80)), &oxm_header, 4);
	// Wildcard Property
	inst_prop.type = htons(OFPTFPT13_WILDCARDS);
	inst_prop.length = htons(8);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-88)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IN_PORT << 1;
	memcpy(buffer + (len-(prop_size-92)), &oxm_header, 4);			
	// Write set field Property
	inst_prop.type = htons(OFPTFPT13_WRITE_SETFIELD);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-96)), &inst_prop, 4);
	// Apply set field Property
	inst_prop.type = htons(OFPTFPT13_APPLY_SETFIELD);
	inst_prop.length = htons(8);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-104)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_VLAN_VID << 1;		
	memcpy(buffer + (len-(prop_size-108)), &oxm_header, 4);		

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
	
	if (iLastFlow > (MAX_FLOWS-1))
	{
		of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
		return;
	}
	
	struct ofp13_flow_mod * ptr_fm;
	ptr_fm = (struct ofp13_flow_mod *) msg;
	memcpy(&flow_match13[iLastFlow], ptr_fm, sizeof(struct ofp13_flow_mod));
	if (ntohs(ptr_fm->match.length) > 4)
	{
		ofp13_oxm_match[iLastFlow] = malloc(ntohs(flow_match13[iLastFlow].match.length)-4);	// Allocate a space to store match fields
		memcpy(ofp13_oxm_match[iLastFlow], ptr_fm->match.oxm_fields, ntohs(flow_match13[iLastFlow].match.length)-4);
	} else {
		ofp13_oxm_match[iLastFlow] = NULL;
	}
	int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
	int instruction_size = ntohs(ptr_fm->header.length) - mod_size;
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

void flow_delete13(struct ofp_header *msg)
{
	struct ofp13_flow_mod *ptr_fm = msg;
	for(int q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if (ptr_fm->table_id != OFPTT13_ALL && ptr_fm->table_id != flow_match13[q].table_id)
				{
						continue;
				}
				if (ptr_fm->cookie_mask != 0 && ptr_fm->cookie != (flow_match13[q].cookie & ptr_fm->cookie_mask))
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
								}
								if(out_group_match==false)
								{
										continue;
								}
						}
						if(field_match13(ofp13_oxm_match[q], ntohs(flow_match13[q].match.length)-4, ptr_fm->match.oxm_fields, ntohs(ptr_fm->match.length)-4) == 0)
						{
								continue;
						}
						if (ptr_fm->flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(q,OFPRR_DELETE);
						// Clear the counters and action
						memset(&flow_counters[q], 0, sizeof(struct flows_counter));
						if(ofp13_oxm_match[q] != NULL)
						{
								free(ofp13_oxm_match[q]);
						}
						if(ofp13_oxm_inst[q] != NULL)
						{
								free(ofp13_oxm_inst[q]);
						}
				}
		}
	
		int flow_count = 0;
		for(int q=0;q<iLastFlow;q++)
		{
			if (flow_counters[q].active){
			if (flow_count != q) {
			memcpy(&flow_counters[flow_count], &flow_counters[q], sizeof(struct flows_counter));
			ofp13_oxm_match[flow_count] = ofp13_oxm_match[q];
			ofp13_oxm_inst[flow_count] = ofp13_oxm_inst[q];
			}
			flow_count++;
		}
	}
	iLastFlow = flow_count;
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
				// Clear the counters and action
				memset(&flow_counters[q], 0, sizeof(struct flows_counter));
				if(ofp13_oxm_match[q] != NULL)
				{
						free(ofp13_oxm_match[q]);
				}
				if(ofp13_oxm_inst[q] != NULL)
				{
						free(ofp13_oxm_inst[q]);
				}
			}
		}
	}
	int flow_count = 0;
	for(int q=0;q<iLastFlow;q++)
	{
		if (flow_counters[q].active){
			if (flow_count != q) {
				memcpy(&flow_counters[flow_count], &flow_counters[q], sizeof(struct flows_counter));
				ofp13_oxm_match[flow_count] = ofp13_oxm_match[q];
				ofp13_oxm_inst[flow_count] = ofp13_oxm_inst[q];
			}
			flow_count++;
		}
	}
	iLastFlow = flow_count;
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
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason)
{
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
	pi->table_id = 0;
	pi->cookie = -1;

	pi->match.type = htons(OFPMT13_OXM);
	pi->match.length = htons(12);
	oxm_header.oxm_class = ntohs(0x8000);
	oxm_header.oxm_field = OFPXMT13_OFB_IN_PORT;
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
	uint32_t outPort = 0;
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
	}
	
	if (outPort == OFPP13_FLOOD)
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



// --- kwi --- //

struct ofp13_filter {
	bool strict;
	uint8_t table_id;
	uint16_t priority;
	uint32_t out_port;
	uint32_t out_group;
	uint64_t cookie;
	uint64_t cookie_mask;
	struct ofp13_match match;
	char *oxm_fields;
};

/*
 * scans flow table for matching flow
 */
int filter_ofp13_flow(int first, struct ofp13_filter filter){
	for(int i=first; i<iLastFlow; i++){
		if (flow_counters[i].active == 0){
			continue;
		}
		if (filter.table_id != OFPTT13_ALL && filter.table_id != flow_match13[i].table_id){
			continue;
		}
		if (filter.cookie_mask != 0 && filter.cookie != (flow_match13[i].cookie & filter.cookie_mask)){
			continue;
		}
		if(filter.strict && filter.priority != flow_match13[i].priority){
			continue;
		}
		if (filter.out_port != OFPP13_ANY){
			bool out_port_match = false;
			int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(flow_match13[i].match.length));
			int instruction_size = ntohs(flow_match13[i].header.length) - mod_size;
			struct ofp13_instruction *inst;
			for(inst=ofp13_oxm_inst[i]; inst<ofp13_oxm_inst[i]+instruction_size; inst+=ntohs(inst->len)){
				if(ntohs(inst->type) == OFPIT13_APPLY_ACTIONS || ntohs(inst->type) == OFPIT13_WRITE_ACTIONS){
					struct ofp13_instruction_actions *ia = inst;
					struct ofp13_action_header *action;
					for(action=ia->actions; action<inst+ntohs(inst->len); action+=ntohs(action->len)){
						if(ntohs(action->type)==OFPAT13_OUTPUT){
							struct ofp13_action_output *output = action;
							if (output->port == filter.out_port){
								out_port_match = true;
							}
						}
					}
				}
			}
			if(out_port_match==false){
				continue;
			}
		}
		if (filter.out_group != OFPG13_ANY){
			bool out_group_match = false;
			int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(flow_match13[i].match.length));
			int instruction_size = ntohs(flow_match13[i].header.length) - mod_size;
			struct ofp13_instruction *inst;
			for(inst=ofp13_oxm_inst[i]; inst<ofp13_oxm_inst[i]+instruction_size; inst+=ntohs(inst->len)){
				if(ntohs(inst->type) == OFPIT13_APPLY_ACTIONS || ntohs(inst->type) == OFPIT13_WRITE_ACTIONS){
					struct ofp13_instruction_actions *ia = inst;
					struct ofp13_action_header *action;
					for(action=ia->actions; action<inst+ntohs(inst->len); action+=ntohs(action->len)){
						if(ntohs(action->type)==OFPAT13_GROUP){
							struct ofp13_action_group *group = action;
							if (group->group_id == filter.out_group){
								out_group_match = true;
							}
						}
					}
				}
			}
			if(out_group_match==false){
				continue;
			}
		}
		if(filter.strict){
			if(field_cmp13(ofp13_oxm_match[i], ntohs(flow_match13[i].match.length)-4,
					filter.oxm_fields, ntohs(filter.match.length)-4) == 0){
				continue;
			}
		} else {
			if(field_match13(ofp13_oxm_match[i], ntohs(flow_match13[i].match.length)-4,
					filter.oxm_fields, ntohs(filter.match.length)-4) == 0){
				continue;
			}
		}
		return i;
	}
	return -1;
}

uint16_t fill_ofp13_flow_stats(const struct ofp13_flow_stats_request *unit, int *index, char *buffer, uint16_t capacity){
	struct ofp13_filter filter = {
		.cookie = unit->cookie,
		.cookie_mask = unit->cookie_mask,
		.out_group = unit->out_group,
		.out_port = unit->out_port,
		.table_id = unit->table_id,
		.match = unit->match,
		.oxm_fields = &unit->match.oxm_fields,
	};
	uint16_t length = 0;
	int k;
	for(k=filter_ofp13_flow(*index, filter); k>=0; k=filter_ofp13_flow(k+1, filter)){
		// ofp_flow_stats fixed fields are the same length with ofp_flow_mod
		if(length + ntohs(flow_match13[k].header.length) > capacity){
			*index = k; // we want to revisit k.
			break;
		}
		int len = 0;
		struct ofp13_flow_stats stats = {0};
		stats.length = flow_match13[k].header.length;
		stats.table_id = flow_match13[k].table_id;
		stats.duration_sec = htonl(totaltime - flow_counters[k].duration); // TODO: reduce timer
		stats.duration_nsec = htonl(0); // TODO: reduce timer
		stats.priority = flow_match13[k].priority;
		stats.idle_timeout = flow_match13[k].idle_timeout;
		stats.hard_timeout = flow_match13[k].hard_timeout;
		stats.flags = flow_match13[k].flags;
		stats.cookie = flow_match13[k].cookie;
		stats.packet_count = htonll(flow_counters[k].hitCount); // TODO: query switch
		stats.byte_count = htonll(flow_counters[k].bytes); // TODO: query switch
		stats.match = flow_match13[k].match;
		// struct ofp13_flow_stats(including ofp13_match)
		memcpy(buffer+length, &stats, sizeof(struct ofp13_flow_stats));
		// oxm_fields
		len = offsetof(struct ofp13_flow_stats, match) + offsetof(struct ofp13_match, oxm_fields);
		memcpy(buffer+length+len, ofp13_oxm_match[k], ntohs(stats.match.length) - 4);
		// instructions
		len = offsetof(struct ofp13_flow_stats, match) + ALIGN8(ntohs(stats.match.length));
		memcpy(buffer+length+len, ofp13_oxm_inst[k], ntohs(stats.length) - len);
		length += ntohs(stats.length);
	}
	if(k<0){
		*index = -1; // complete
	}
	return length;
}

static uint16_t add_ofp13_flow(const struct ofp13_flow_mod *req){
	uint16_t flags = ntohs(req->flags);
	if((flags & OFPFF13_CHECK_OVERLAP) != 0){
		int overlap = -1;
		for(int i=0; i<iLastFlow; i++){
			if(flow_counters[i].active==false
					|| req->table_id != flow_match13[i].table_id
					|| req->priority != flow_match13[i].priority){
				continue;
			}
			if(field_match13(req->match.oxm_fields, htons(req->match.length)-4,
			ofp13_oxm_match[i], htons(flow_match13[i].match.length)-4) != 1){
				overlap = i;
				break;
			}
			if(field_match13(ofp13_oxm_match[i], htons(flow_match13[i].match.length)-4,
			req->match.oxm_fields, htons(req->match.length)-4) != 1){
				overlap = i;
				break;
			}
		}
		if(overlap >= 0){
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_OVERLAP);
		}
	}
	int found = -1;
	for(int i=0; i<iLastFlow; i++){
		if(flow_counters[i].active==false
				|| req->table_id != flow_match13[i].table_id
				|| req->priority != flow_match13[i].priority){
			continue;
		}
		if(field_match13(req->match.oxm_fields, htons(req->match.length)-4,
				ofp13_oxm_match[i], htons(flow_match13[i].match.length)-4) != 1){
			continue;
		}
		if(field_match13(ofp13_oxm_match[i], htons(flow_match13[i].match.length)-4,
				req->match.oxm_fields, htons(req->match.length)-4) != 1){
			continue;
		}
		found = i; // identical flow found.
		break;
	}
	int n = found;
	if(n < 0){
		n = iLastFlow++;
	}
	memcpy(&flow_match13[n], req, sizeof(struct ofp13_flow_mod));
	if(ofp13_oxm_match[n] != NULL){
		free(ofp13_oxm_match[n]);
	}
	if(req->match.length > 4){
		ofp13_oxm_match[n] = malloc(ntohs(flow_match13[iLastFlow].match.length)-4);	// Allocate a space to store match fields
		memcpy(ofp13_oxm_match[n], req->match.oxm_fields, ntohs(req->match.length)-4);
	}else{
		ofp13_oxm_match[n] = NULL;
	}
	if(ofp13_oxm_inst[n] != NULL){
		free(ofp13_oxm_inst[n]);
	}
	uint16_t inst_offset = 0;
	inst_offset += offsetof(struct ofp13_flow_mod, match);
	inst_offset += ALIGN8(ntohs(req->match.length));
	uint16_t inst_length = ntohs(req->header.length) > inst_offset;
	if(inst_length > 0){
		const char *p = (const char*)req;
		ofp13_oxm_inst[n] = malloc(inst_length);
		memcpy(ofp13_oxm_inst[n], p+inst_offset, inst_length);
	} else {
		ofp13_oxm_inst[n] = NULL;
	}
	if((flags & OFPFF13_RESET_COUNTS) != 0){
		flow_counters[n].hitCount = 0;
		flow_counters[n].bytes = 0;
	}
	flow_counters[n].active = true;
	return 0;
}

static uint16_t modify_ofp13_flow(const struct ofp13_flow_mod *req, bool strict){
	struct ofp13_filter filter = {
		.cookie = req->cookie,
		.cookie_mask = req->cookie_mask,
		.out_port = req->out_port,
		.out_group = req->out_group,
		.table_id = req->table_id,
		.match = req->match,
		.oxm_fields = req->match.oxm_fields,
		.strict = strict,
		.priority = req->priority,
	};
	int k;
	for(k=filter_ofp13_flow(*index, filter); k>=0; k=filter_ofp13_flow(k+1, filter)){
		if(ofp13_oxm_inst[k] != NULL){
			free(ofp13_oxm_inst[k]);
		}

		uint16_t inst_offset = 0;
		inst_offset += offsetof(struct ofp13_flow_mod, match);
		inst_offset += ALIGN8(ntohs(req->match.length));
		
		uint16_t inst_length = ntohs(req->header.length) > inst_offset;
		if(inst_length > 0){
			const char *p = (const char*)req;
			ofp13_oxm_inst[k] = malloc(inst_length);
			memcpy(ofp13_oxm_inst[k], p+inst_offset, inst_length);
		} else {
			ofp13_oxm_inst[k] = NULL;
		}
	}
	return 0;
}

uint16_t mod_ofp13_flow(struct ofp13_flow_mod *req){
	uint16_t ret;
	switch(req->command){
		case OFPFC13_ADD:
			ret = add_ofp13_flow(req);
		break;
		
		case OFPFC_MODIFY:
			ret = modify_ofp13_flow(req, false);
		break;
		
		case OFPFC_MODIFY_STRICT:
			ret = modify_ofp13_flow(req, true);
		break;
		
		case OFPFC13_DELETE:
//		flow_delete13(req);
		break;
		
		case OFPFC13_DELETE_STRICT:
//		flow_delete_strict13(req);
		break;
		
		default:
			// TODO: add error
		break;
	}
	if(req->buffer_id != OFP13_NO_BUFFER && ret != 0){
		// TODO: enqueue buffer
	}
	return ret;
}

