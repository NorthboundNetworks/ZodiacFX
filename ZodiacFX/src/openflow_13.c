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
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>
#include <lwip/udp.h>
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "timers.h"

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
		if (flow_counters[i].active){
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
extern struct fx_flow fx_flows[MAX_FLOWS];
extern struct fx_flow_timeout fx_flow_timeouts[MAX_FLOWS];
extern struct fx_flow_count fx_flow_counts[MAX_FLOWS];
extern uint32_t fx_buffer_id;
extern struct fx_packet_in fx_packet_ins[MAX_BUFFERS];

uint16_t send_ofp13_flow_rem(struct ofp_pcb *self){
	// TODO
	return 0;
}

// fields are in host byte order
struct ofp13_filter {
	bool strict;
	uint8_t table_id;
	uint16_t priority;
	uint32_t out_port;
	uint32_t out_group;
	uint64_t cookie; // in network byte order
	uint64_t cookie_mask; // in network byte order
	uint16_t oxm_length;
	const char *oxm;
};

/*
 * scans flow table for matching flow
 */
int filter_ofp13_flow(int first, struct ofp13_filter filter){
	for(int i=first; i<iLastFlow; i++){
		if(fx_flows[i].active != FX_FLOW_ACTIVE){
			continue;
		}
		if (filter.table_id != OFPTT13_ALL && filter.table_id != fx_flows[i].table_id){
			continue;
		}
		if (filter.cookie_mask != 0 && filter.cookie != (fx_flows[i].cookie & filter.cookie_mask)){
			continue;
		}
		if(filter.strict){
			if (filter.priority != fx_flows[i].priority){
				continue;
			}
			if(false == oxm_strict_equals(fx_flows[i].oxm, fx_flows[i].oxm_length, filter.oxm, filter.oxm_length)){
				continue;
			}
		} else {
			if(field_match13(fx_flows[i].oxm, fx_flows[i].oxm_length, filter.oxm, filter.oxm_length) == 0){
				continue;
			}
		}
		if (filter.out_port != OFPP13_ANY){
			bool out_port_match = false;
			const char *ops = fx_flows[i].ops;
			while(ops < fx_flows[i].ops+fx_flows[i].ops_length){
				struct ofp13_instruction *inst = (struct ofp13_instruction*)ops;
				if(inst->type==htons(OFPIT13_APPLY_ACTIONS) || inst->type==htons(OFPIT13_WRITE_ACTIONS)){
					struct ofp13_instruction_actions *ia = (struct ofp13_instruction_actions*)inst;
					const char *act = (const char*)ia->actions;
					while(act < ops+ntohs(inst->len)){
						struct ofp13_action_header *action = (struct ofp13_action_header*)act;
						if(action->type==htons(OFPAT13_OUTPUT)){
							struct ofp13_action_output *output = (struct ofp13_action_output*)action;
							if (output->port == filter.out_port){
								out_port_match = true;
							}
						}
						act += ntohs(action->len);
					}
				}
				ops += ntohs(inst->len);
			}
			if(out_port_match==false){
				continue;
			}
		}
		if (filter.out_group != OFPG13_ANY){
			bool out_group_match = false;
			const char *ops = fx_flows[i].ops;
			while(ops < fx_flows[i].ops+fx_flows[i].ops_length){
				struct ofp13_instruction *inst = (struct ofp13_instruction*)ops;
				if(inst->type==htons(OFPIT13_APPLY_ACTIONS) || inst->type==htons(OFPIT13_WRITE_ACTIONS)){
					struct ofp13_instruction_actions *ia = (struct ofp13_instruction_actions*)inst;
					const char *act = (const char*)ia->actions;
					while(act < ops+ntohs(inst->len)){
						struct ofp13_action_header *action = (struct ofp13_action_header*)act;
						if(action->type==htons(OFPAT13_GROUP)){
							struct ofp13_action_group *group = (struct ofp13_action_group*)action;
							if (group->group_id == filter.out_group){
								out_group_match = true;
							}
						}
						act += ntohs(action->len);
					}
				}
				ops += ntohs(inst->len);
			}
			if(out_group_match==false){
				continue;
			}
		}
		return i;
	}
	return -1;
}

uint16_t fill_ofp13_flow_stats(const struct ofp13_flow_stats_request *unit, int *mp_index, char *buffer, uint16_t capacity){
	struct ofp13_filter filter = {
		.cookie = unit->cookie,
		.cookie_mask = unit->cookie_mask,
		.out_group = ntohl(unit->out_group),
		.out_port = ntohl(unit->out_port),
		.table_id = unit->table_id,
		.oxm_length = ntohs(unit->match.length)-4,
		.oxm = &unit->match.oxm_fields,
	};
	uint16_t length = 0;
	int i;
	for(i=filter_ofp13_flow(*mp_index, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		uint16_t offset_inst = offsetof(struct ofp13_flow_stats, match) + ALIGN8(4+fx_flows[i].oxm_length);		;
		// ofp_flow_stats fixed fields are the same length with ofp_flow_mod
		if(length + offset_inst + fx_flows[i].ops_length > capacity){
			*mp_index = i; // we want to revisit k.
			break;
		}
		uint32_t duration = sys_get_ms() - fx_flow_timeouts[i].init;
		struct ofp13_flow_stats stats = {
			.length = htons(offset_inst+fx_flows[i].ops_length),
			.table_id = fx_flows[i].table_id,
			.duration_sec = htonl(duration/1000U),
			.duration_nsec = htonl((duration%1000U)*1000000U),
			.priority = htons(fx_flows[i].priority),
			.idle_timeout = htons(fx_flow_timeouts[i].idle_timeout),
			.hard_timeout = htons(fx_flow_timeouts[i].hard_timeout),
			.flags = htons(fx_flows[i].flags),
			.cookie = fx_flows[i].cookie,
			.packet_count = htonll(fx_flow_counts[i].packet_count),
			.byte_count = htonll(fx_flow_counts[i].byte_count),
			.match = {
				.type = htons(OFPMT13_OXM),
				.length = htons(4+fx_flows[i].oxm_length),
			}
		};
		int len;
		// struct ofp13_flow_stats(including ofp13_match)
		memcpy(buffer+length, &stats, sizeof(struct ofp13_flow_stats));
		// oxm_fields
		len = offsetof(struct ofp13_flow_stats, match) + offsetof(struct ofp13_match, oxm_fields);
		memcpy(buffer+length+len, fx_flows[i].oxm, fx_flows[i].oxm_length);
		// instructions
		len = offset_inst;
		memcpy(buffer+length+len, fx_flows[i].ops, fx_flows[i].ops_length);
		length += offset_inst + fx_flows[i].ops_length;
	}
	if(i<0){
		*mp_index = -1; // complete
	}
	return length;
}

static uint16_t add_ofp13_flow(const struct ofp13_flow_mod *req){
	if(req->table_id > OFPP13_MAX){
		return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_TABLE_ID);
	}
	if((req->flags & htons(OFPFF13_CHECK_OVERLAP)) != 0){
		int overlap = -1;
		for(int i=0; i<iLastFlow; i++){
			if(fx_flows[i].active != FX_FLOW_ACTIVE
					|| req->table_id != fx_flows[i].table_id
					|| req->priority != fx_flows[i].priority){
				continue;
			}
			if(field_match13(req->match.oxm_fields, ntohs(req->match.length)-4,
					fx_flows[i].oxm, fx_flows[i].oxm_length) != 1){
				overlap = i;
				break;
			}
			if(field_match13(fx_flows[i].oxm, fx_flows[i].oxm_length,
					req->match.oxm_fields, ntohs(req->match.length)-4) != 1){
				overlap = i;
				break;
			}
		}
		if(overlap >= 0){
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_OVERLAP);
		}
	}

	struct ofp13_filter filter = {
		.strict = true,
		.table_id = req->table_id,
		.priority = ntohs(req->priority),
		.out_port = OFPP13_ANY,
		.out_group = OFPG13_ANY,
		.cookie = req->cookie,
		.cookie_mask = req->cookie_mask,
		.oxm_length = ntohs(req->match.length)-4,
		.oxm = req->match.oxm_fields,
	};
	int found = filter_ofp13_flow(0, filter);
	int n = found;
	if(n < 0){
		for(int i=0; i<iLastFlow; i++){
			if(fx_flows[i].active == 0){
				n = i;
				break;
			}
		}
	}
	if(n < 0){
		if(iLastFlow >= MAX_FLOWS){
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
		}else{
			n = iLastFlow++;
		}
	}
	uint16_t offset = offsetof(struct ofp13_flow_mod, match) + ALIGN8(ntohs(req->match.length));
	uint16_t oxm_len = ntohs(req->match.length) - 4;
	uint16_t ops_len = ntohs(req->header.length) - offset;
	const char *oxm = malloc(oxm_len);
	const char *ops = malloc(ops_len);
	if(oxm==NULL || ops==NULL){
		if(oxm!=NULL) free(oxm);
		if(ops!=NULL) free(ops);
		return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
	}
	
	fx_flows[n].active = FX_FLOW_ACTIVE;
	fx_flows[n].table_id = req->table_id;
	fx_flows[n].priority = ntohs(req->priority);
	fx_flows[n].flags = ntohs(req->flags);
	if(fx_flows[n].oxm){
		free(fx_flows[n].oxm);
	}
	memcpy(oxm, req->match.oxm_fields, oxm_len);
	fx_flows[n].oxm = oxm;
	fx_flows[n].oxm_length = oxm_len;
	if(fx_flows[n].ops){
		free(fx_flows[n].ops);
	}
	memcpy(ops, (const char*)req + offset, ops_len);
	fx_flows[n].ops = ops;
	fx_flows[n].ops_length = ops_len;
	fx_flows[n].cookie = req->cookie;
	
	if(found < 0 || (req->flags & htons(OFPFF13_RESET_COUNTS)) != 0){
		fx_flow_counts[n].byte_count = 0;
		fx_flow_counts[n].packet_count = 0;
	}
	if(ntohl(req->buffer_id) != OFP13_NO_BUFFER){
		// TODO: enqueue buffer
	}
	return 0;
}

static uint16_t modify_ofp13_flow(const struct ofp13_flow_mod *req, bool strict){
	if(req->table_id > OFPP13_MAX){
		return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_TABLE_ID);
	}

	struct ofp13_filter filter = {
		.strict = strict,
		.table_id = req->table_id,
		.priority = ntohs(req->priority),
		.out_port = OFPP13_ANY,
		.out_group = OFPG13_ANY,
		.cookie = req->cookie,
		.cookie_mask = req->cookie_mask,
		.oxm_length = ntohs(req->match.length)-4,
		.oxm = req->match.oxm_fields,
	};

	uint16_t inst_offset = offsetof(struct ofp13_flow_mod, match) + ALIGN8(ntohs(req->match.length));
	uint16_t inst_length = ntohs(req->header.length) - inst_offset;
	
	int count = 0;
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		count++;
	}
	const char **tmp = malloc(count*sizeof(const char*));
	for(int i=0; i<count; i++){
		tmp[i] = malloc(inst_length);
		if(tmp[i]==NULL){
			for(int j=0; j<i; j++){
				free(tmp[j]);
			}
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
		}
	}
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		if(fx_flows[i].ops != NULL){
			free(fx_flows[i].ops);
		}
		fx_flows[i].ops = tmp[--count];
		memcpy(fx_flows[i].ops, (const char*)req + inst_offset, inst_length);
		fx_flows[i].ops_length = inst_length;
		
		if((req->flags & htons(OFPFF13_RESET_COUNTS)) != 0){
			fx_flow_counts[i].byte_count = 0;
			fx_flow_counts[i].packet_count = 0;
		}
	}
	free(tmp);
	if(req->buffer_id != htonl(OFP13_NO_BUFFER)){
		// TODO: enqueue buffer
	}
	return 0;
}

static uint16_t delete_ofp13_flow(const struct ofp13_flow_mod *req, bool strict){
	struct ofp13_filter filter = {
		.strict = strict,
		.table_id = req->table_id,
		.priority = ntohs(req->priority),
		.out_port = ntohl(req->out_port),
		.out_group = ntohl(req->out_group),
		.cookie = req->cookie,
		.cookie_mask = req->cookie_mask,
		.oxm_length = ntohs(req->match.length)-4,
		.oxm = req->match.oxm_fields,
	};
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		if(fx_flows[i].flags & OFPFF13_SEND_FLOW_REM != 0){
			fx_flows[i].active = FX_FLOW_SEND_FLOW_REM;
		} else {
			fx_flows[i].active = 0;
		}
	}
	return 0;
}

uint16_t mod_ofp13_flow(struct ofp13_flow_mod *req){
	uint16_t ret;
	switch(ntohs(req->command)){
		case OFPFC13_ADD:
			return add_ofp13_flow(req);
		
		case OFPFC_MODIFY:
			return modify_ofp13_flow(req, false);
		
		case OFPFC_MODIFY_STRICT:
			return modify_ofp13_flow(req, true);
		
		case OFPFC13_DELETE:
			return delete_ofp13_flow(req, false);
		
		case OFPFC13_DELETE_STRICT:
			return delete_ofp13_flow(req, true);
		
		default:
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_COMMAND);
	}
}

// kwi //

static int bits_on(const char *data, int len){
	int r = 0;
	for(int i=0; i<len; i++){
		if(data[i]&0x80) r++;
		if(data[i]&0x40) r++;
		if(data[i]&0x20) r++;
		if(data[i]&0x10) r++;
		if(data[i]&0x08) r++;
		if(data[i]&0x04) r++;
		if(data[i]&0x02) r++;
		if(data[i]&0x01) r++;
	}
	return r;
}

int match_frame_by_oxm(struct fx_packet packet, struct fx_packet_oob oob, const char *oxm, uint16_t oxm_length){
	int count = 0;
	for(const char *pos=oxm; pos<oxm+oxm_length; pos+=oxm[3]){
		if(pos[0]==0x80 && pos[1]==0x00){
			int has_mask = pos[2] & 0x01;
			switch(pos[2]>>1){
				case OFPXMT13_OFB_IN_PORT:
				if(memcmp(&packet.in_port, pos+4, 4)!=0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_IN_PHY_PORT:
				if(memcmp(&packet.in_phy_port, pos+4, 4) != 0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_METADATA:
				{
					uint64_t value;
					if(has_mask){
						memcpy(value, pos+12, 8);
						value &= packet.metadata;
						count += bits_on(pos+12, 8);
					} else {
						value = packet.metadata;
						count += 64;
					}
					if(memcmp(&value, pos+4, 8)!=0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_ETH_DST:
				{
					char mac[6];
					pbuf_copy_partial(packet.data, mac, 6, 0);
					if(has_mask){
						for(int i=0; i<6; i++){
							mac[i] &= pos[10+i];
						}
						count += bits_on(pos+10, 6);
					}else{
						count += 48;
					}
					if(memcmp(mac, pos+4, 6) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_ETH_SRC:
				{
					char mac[6];
					pbuf_copy_partial(packet.data, mac, 6, 6);
					if(has_mask){
						for(int i=0; i<6; i++){
							mac[i] &= pos[10+i];
						}
						count += bits_on(pos+10, 6);
					} else {
						count += 48;
					}
					if(memcmp(mac, pos+4, 6) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_ETH_TYPE:
				if(memcmp(oob.eth_type, pos+4, 2) != 0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_VLAN_VID:
				{
					uint16_t vlan;
					if(has_mask){
						memcpy(&vlan, pos+6, 2);
						vlan &= oob.vlan & htons(0x1FFF);
						count += bits_on(pos+6, 2);
					} else {
						vlan = oob.vlan & htons(0x1FFF);
						count += 16;
					}
					if(memcmp(&vlan, pos+4, 2) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_VLAN_PCP:
				{
					if((oob.vlan & htons(0x1000)) == 0){
						return -1;
					}
					uint8_t pcp;
					pcp = ntohs(oob.vlan)>>13;
					if(has_mask){
						pcp &= pos[5];
						count += bits_on(pos+5, 1);
					} else {
						count += 8;
					}
					if(pcp != pos[4]){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_IP_DSCP:
				{
					uint8_t dscp;
					if(oob.eth_type == htons(0x0800)){
						struct ip_hdr *hdr = packet.data->payload + oob.eth_offset;
						dscp = IPH_TOS(hdr)>>2;
					} else if(oob.eth_type == htons(0x86dd)){
						return -1; // TODO
					} else {
						return -1;
					}
					if(dscp != pos[4]){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_IP_ECN:
				{
					uint8_t ecn;
					if(oob.eth_type == htons(0x0800)){
						struct ip_hdr *hdr = packet.data->payload + oob.eth_offset;
						ecn = IPH_TOS(hdr)&0x03;
					} else if(oob.eth_type == htons(0x86dd)){
						return -1; // TODO
					} else {
						return -1;
					}
					if(ecn != pos[4]){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_IPV4_SRC:
				if(oob.eth_type == htons(0x0800)){
					struct ip_hdr *hdr = packet.data->payload + oob.eth_offset;
					uint32_t value;
					if(has_mask){
						memcpy(&value, pos+8, 4);
						value &= hdr->src.addr;
						count += bits_on(pos+8, 4);
					} else {
						value = hdr->src.addr;
						count += 32;
					}
					if(memcmp(&value, pos+4, 4)!=0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_IPV4_DST:
				if(oob.eth_type == htons(0x0800)){
					struct ip_hdr *hdr = packet.data->payload + oob.eth_offset;
					uint32_t value;
					if(has_mask){
						memcpy(&value, pos+8, 4);
						value &= hdr->dest.addr;
						count += bits_on(pos+8, 4);
					} else {
						value = hdr->dest.addr;
						count += 32;
					}
					if(memcmp(&value, pos+4, 4)!=0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_TCP_SRC:
				{
					if(oob.eth_type != htons(0x0800)){
						return -1;
					}
					struct ip_hdr *iphdr = (struct ip_hdr *)(packet.data->payload + oob.eth_offset);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct tcp_hdr *tcphdr = (struct tcp_hdr *)(packet.data->payload
						+ oob.eth_offset + IPH_HL(iphdr) * 4);
					if(memcmp(&(tcphdr->src), pos+4, 2) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_TCP_DST:
				{
					if(oob.eth_type != htons(0x0800)){
						return -1;
					}
					struct ip_hdr *iphdr = (struct ip_hdr *)(packet.data->payload + oob.eth_offset);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct tcp_hdr *tcphdr = (struct tcp_hdr *)(packet.data->payload
						+ oob.eth_offset + IPH_HL(iphdr) * 4);
					if(memcmp(&(tcphdr->dest), pos+4, 2) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_UDP_SRC:
				{
					if(oob.eth_type != htons(0x0800)){
						return -1;
					}
					struct ip_hdr *iphdr = (struct ip_hdr *)(packet.data->payload + oob.eth_offset);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct udp_hdr *udphdr = (struct udp_hdr *)(packet.data->payload
						+ oob.eth_offset + IPH_HL(iphdr) * 4);
					if(memcmp(&(udphdr->src), pos+4, 2) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_UDP_DST:
				{
					if(oob.eth_type != htons(0x0800)){
						return -1;
					}
					struct ip_hdr *iphdr = (struct ip_hdr *)(packet.data->payload + oob.eth_offset);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct udp_hdr *udphdr = (struct udp_hdr *)(packet.data->payload
						+ oob.eth_offset + IPH_HL(iphdr) * 4);
					if(memcmp(&(udphdr->dest), pos+4, 2) != 0){
						return -1;
					}
				}
				break;
			}
		}
	}
	return count;
}

static void execute_ofp13_action(struct fx_packet *packet, struct fx_packet_oob *oob, struct ofp13_action_header *act, int flow){
	switch(ntohs(act->type)){
		case OFPAT13_OUTPUT:
		{
			struct ofp13_action_output *out = act;
			uint32_t port = ntohl(out->port);
			if(port == OFPP13_CONTROLLER){
				
			}
		}
	}
}

void execute_ofp13_flow(struct fx_packet *packet, struct fx_packet_oob *oob, int flow){
	const char* insts[6] = {};
	const char *pos = fx_flows[flow].ops;
	while(pos < fx_flows[flow].ops+fx_flows[flow].ops_length){
		struct ofp13_instruction *hdr = (struct ofp13_instruction*)pos;
		uint16_t itype = ntohs(hdr->type) - 1;
		if(itype < 6){
			insts[itype] = pos;
		}
		pos += ntohs(hdr->len);
	}
	
	pos = insts[OFPIT13_METER-1];
	if(pos != NULL){
		// todo
	}
	pos = insts[OFPIT13_APPLY_ACTIONS-1];
	if(pos != NULL){
		struct ofp13_instruction_actions *ia = pos;
		const char *p = ia->actions;
		while(p < pos+ntohs(ia->len)){
			struct ofp13_action_header *act = p;
			execute_ofp13_action(&packet, &oob, act, flow);
			p += ntohs(act->len);
		}
	}
	pos = insts[OFPIT13_CLEAR_ACTIONS-1];
	if(pos != NULL){
		
	}
	pos = insts[OFPIT13_WRITE_ACTIONS-1];
	if(pos != NULL){
		
	}
	pos = insts[OFPIT13_WRITE_METADATA-1];
	if(pos != NULL){
		
	}
	pos = insts[OFPIT13_GOTO_TABLE-1];
	if(pos != NULL){
		
	}else{
		// TODO execute action-set
	}
}
