/**
 * @file
 * openflow_10.c
 *
 * This file contains the OpenFlow v1.0 (0x01) specific functions
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
#include "of_helper.h"
#include "trace.h"
#include "lwip/tcp.h"
#include "ipv4/lwip/ip.h"
#include "lwip/tcp_impl.h"
#include "lwip/udp.h"

// Global variables
extern struct zodiac_config Zodiac_Config;
extern int totaltime;
extern struct tcp_pcb *tcp_pcb;
extern int iLastFlow;
extern struct ofp_flow_mod *flow_match10[MAX_FLOWS_10];
extern struct flows_counter flow_counters[MAX_FLOWS_13];
extern struct flow_tbl_actions *flow_actions10[MAX_FLOWS_10];
extern struct table_counter table_counters[MAX_TABLES];
extern int OF_Version;
extern bool rcv_freq;
extern uint8_t NativePortMatrix;
extern struct ofp10_port_stats phys10_port_stats[TOTAL_PORTS];
extern uint8_t port_status[TOTAL_PORTS];
extern uint8_t shared_buffer[SHARED_BUFFER_LEN];
extern struct zodiac_config Zodiac_Config;
extern struct ofp_switch_config Switch_config;

//Internal Functions
void packet_in(uint8_t *buffer, uint16_t ul_size, uint32_t port, uint8_t reason);
void features_reply10(uint32_t xid);
void set_config10(struct ofp_header * msg);
void config_reply(uint32_t xid);
void stats10_desc_reply(struct ofp_stats_request * req);
void stats_flow_reply(struct ofp_stats_request * req);
void stats_table_reply(struct ofp_stats_request * req);
void stats_port_reply(struct ofp_stats_request * req);
void packet_out(struct ofp_header * msg);
void flow_mod(struct ofp_header * msg);
void vendor_reply(uint32_t xid);
void flow_add(struct ofp_header * msg);
void flow_modify(struct ofp_header * msg);
void flow_modify_strict(struct ofp_header * msg);
void flow_delete(struct ofp_header * msg);
void flow_delete_strict(struct ofp_header * msg);
void of10_error(struct ofp_header *msg, uint16_t type, uint16_t code);

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

/*
*	Main OpenFlow flow processing function
*
*	@param *p_uc_data - pointer to the buffer containing the packet.
*	@param ul_size - size of the packet.
*	@param port - the port that the packet was received on.
*
*/
void nnOF10_tablelookup(uint8_t *p_uc_data, uint32_t *ul_size, int port)
{
	uint16_t packet_size;
	struct packet_fields fields = {0};
	packet_fields_parser(p_uc_data, &fields);

	memcpy(&packet_size, ul_size, 2);
	uint16_t eth_prot;
	memcpy(&eth_prot, p_uc_data + 12, 2);

	struct ofp_action_output *action_out;	// Need to move these
	struct ofp_action_dl_addr *action_setdl;
	struct ofp_action_nw_addr *action_setnw;
	struct ofp_action_nw_tos *action_settos;
	struct ofp_action_vlan_vid *action_vlanid;
	struct ofp_action_vlan_pcp *action_vlanpcp;
	struct ofp_action_tp_port *action_port;
	struct ofp_action_header *act_hdr;

	uint16_t vlanid;
	uint16_t pcp;
	uint16_t vlanid_mask = htons(0x0fff);
	uint16_t tcpport;
	uint32_t ipadr;
	uint16_t vlantag = htons(0x8100);
	int outport = 0;

	table_counters[0].lookup_count++;

	if (Zodiac_Config.OFEnabled == OF_ENABLED && iLastFlow == 0) // Check to if the flow table is empty
	{
		packet_in (p_uc_data, packet_size, port, OFPR_NO_MATCH); // Packet In if there are no flows in the table
		return;
	}

	if (Zodiac_Config.OFEnabled == OF_ENABLED && iLastFlow > 0) // Main lookup
	{
		int i = -1;
		// Check if packet matches an existing flow
		i = flowmatch10(p_uc_data, port, &fields);
		if (i == -2) return;	// Error packet
		if (i == -1)	// No match
		{
			packet_in (p_uc_data, packet_size, port, OFPR_NO_MATCH);
			return;
		}

		if ( i > -1)
		{
			flow_counters[i].hitCount++; // Increment flow hit count
			flow_counters[i].bytes += packet_size;
			flow_counters[i].lastmatch = (totaltime/2); // Increment flow hit count
			table_counters[0].matched_count++;
			table_counters[0].byte_count += packet_size;

			// If there are no actions DROP the packet
			act_hdr = flow_actions10[i]->action1;
			if(act_hdr->len == 0 )
			{
				return;
			}

			// Apply each action included action
			for(int q=0;q<4;q++)
			{
				if(q == 0) act_hdr = flow_actions10[i]->action1;
				if(q == 1) act_hdr = flow_actions10[i]->action2;
				if(q == 2) act_hdr = flow_actions10[i]->action3;
				if(q == 3) act_hdr = flow_actions10[i]->action4;

				if (act_hdr->len != 0)
				{
					switch(ntohs(act_hdr->type))
					{
						case OFPAT10_OUTPUT:
						action_out = act_hdr;
						if (ntohs(action_out->port) <= 255 && ntohs(action_out->port) != port) // physical port
						{
							outport = (1<< (ntohs(action_out->port)-1));
							gmac_write(p_uc_data, packet_size, outport);
						}

						if (ntohs(action_out->port) == OFPP_IN_PORT)
						{
							outport = (1<< (port-1));
							gmac_write(p_uc_data, packet_size, outport);
						}

						if (ntohs(action_out->port) == OFPP_ALL || ntohs(action_out->port) == OFPP_FLOOD)
						{
							outport = (15 - NativePortMatrix) - (1<<(port-1));
							gmac_write(p_uc_data, packet_size, outport);
						}

						if (ntohs(action_out->port) == OFPP_CONTROLLER)
						{
							int pisize = ntohs(action_out->max_len);
							if (pisize > packet_size) pisize = packet_size;
							packet_in(p_uc_data, pisize, port, OFPR_ACTION);
						}
						break;

						case OFPAT10_SET_DL_SRC:
						action_setdl  = act_hdr;
						memcpy(p_uc_data + 6, action_setdl->dl_addr, 6);
						break;

						case OFPAT10_SET_DL_DST:
						action_setdl  = act_hdr;
						memcpy(p_uc_data, action_setdl->dl_addr, 6);
						break;

						case OFPAT10_SET_NW_SRC:
						action_setnw  = act_hdr;
						ipadr = action_setnw->nw_addr;
						if (eth_prot == vlantag)	// Add 4 bytes to the offset
						{
							memcpy(p_uc_data + 30, &ipadr, 4);
							set_ip_checksum(p_uc_data, packet_size, 18);
						} else {
							memcpy(p_uc_data + 26, &ipadr, 4);
							set_ip_checksum(p_uc_data, packet_size, 14);
						}
						break;

						case OFPAT10_SET_NW_DST:
						action_setnw  = act_hdr;
						ipadr = action_setnw->nw_addr;
						if (eth_prot == vlantag)	// Add 4 bytes to the offset
						{
							memcpy(p_uc_data + 34, &ipadr, 4);
							set_ip_checksum(p_uc_data, packet_size, 18);
						} else {
							memcpy(p_uc_data + 30, &ipadr, 4);
							set_ip_checksum(p_uc_data, packet_size, 14);
						}
						break;

						case OFPAT10_SET_NW_TOS:
						action_settos = act_hdr;
						if (eth_prot == vlantag)
						{
							p_uc_data[19] = action_settos->nw_tos;
							set_ip_checksum(p_uc_data, packet_size, 18);
							} else {
							p_uc_data[15] = action_settos->nw_tos;
							set_ip_checksum(p_uc_data, packet_size, 14);
						}
						break;

						case OFPAT10_SET_VLAN_VID:
						action_vlanid  = act_hdr;
						if (eth_prot == vlantag)
						{
							memcpy(pcp, p_uc_data + 14, 2);
						} else {
							pcp = 0;
						}
						if (action_vlanid->vlan_vid == 0xffff)
						{
							vlanid = pcp & ~vlanid_mask;
						} else {
							vlanid = (action_vlanid->vlan_vid & vlanid_mask) | (pcp & ~vlanid_mask);
						}
						// Does the packet have a VLAN header?
						if (eth_prot == vlantag)
						{
							memcpy(p_uc_data + 14, &vlanid, 2);
						} else {
							memmove(p_uc_data + 16, p_uc_data + 12, packet_size - 12);
							memcpy(p_uc_data + 12, &vlantag,2);
							memcpy(p_uc_data + 14, &vlanid, 2);
							packet_size += 4;
							memcpy(ul_size, &packet_size, 2);
						}
						break;

						case OFPAT10_SET_VLAN_PCP:
						action_vlanpcp = act_hdr;
						if (eth_prot == vlantag)
						{
							memcpy(vlanid, p_uc_data + 14, 2);
						} else {
							vlanid = 0;
						}
						pcp = ((uint16_t)action_vlanpcp->vlan_pcp)<<13;
						vlanid = (vlanid & vlanid_mask) | (htons(pcp) & ~vlanid_mask);
						// Does the packet have a VLAN header?
						if (eth_prot == vlantag)
						{
							memcpy(p_uc_data + 14, &vlanid, 2);
						} else {
							memmove(p_uc_data + 16, p_uc_data + 12, packet_size - 12);
							memcpy(p_uc_data + 12, &vlantag,2);
							memcpy(p_uc_data + 14, &vlanid, 2);
							packet_size += 4;
							memcpy(ul_size, &packet_size, 2);
						}
						break;

						case OFPAT10_STRIP_VLAN:
						if (eth_prot == vlantag)
						{
							memmove(p_uc_data + 12, p_uc_data + 16, packet_size - 16);
							packet_size -= 4;
							memcpy(ul_size, &packet_size, 2);
						}
						break;

						case OFPAT10_SET_TP_DST:
						action_port = act_hdr;
						tcpport = action_port->tp_port;

						if (eth_prot == vlantag)	// Add 4 bytes to the offset
						{
							memcpy(p_uc_data + 40, &tcpport, 2);
							} else {
							memcpy(p_uc_data + 36, &tcpport, 2);
						}
						break;

						case OFPAT10_SET_TP_SRC:
						action_port = act_hdr;
						tcpport = action_port->tp_port;
						if (eth_prot == vlantag)	// Add 4 bytes to the offset
						{
							memcpy(p_uc_data + 38, &tcpport, 2);
							set_ip_checksum(p_uc_data, packet_size, 18);
							} else {
							memcpy(p_uc_data + 34, &tcpport, 2);
							set_ip_checksum(p_uc_data, packet_size, 14);
						}
						break;
					};
				}
			}
		}

		return;
	}
	return;	// Should only get to here if the action is unknown
}

void of10_message(struct ofp_header *ofph, int len)
{
	struct ofp_stats_request *stats_req;
	switch(ofph->type)
	{
		case OFPT10_FEATURES_REQUEST:
		rcv_freq = true;
		features_reply10(ofph->xid);
		break;

		case OFPT10_SET_CONFIG:
		set_config10(ofph);
		break;

		case OFPT10_STATS_REQUEST:
		stats_req  = (struct ofp_stats_request *) ofph;
		if ( HTONS(stats_req->type) == OFPST_DESC )
		{
			stats10_desc_reply(stats_req);
		}

		if ( HTONS(stats_req->type) == OFPST_FLOW )
		{
			stats_flow_reply(stats_req);
		}

		if ( HTONS(stats_req->type) == OFPST_AGGREGATE )
		{
			//stats_reply_aggregate(stats_req);
		}

		if ( HTONS(stats_req->type) == OFPST_TABLE )
		{
			stats_table_reply(stats_req);
		}

		if ( HTONS(stats_req->type) == OFPST_PORT )
		{

			stats_port_reply(stats_req);
		}

		if ( HTONS(stats_req->type) == OFPST_VENDOR )
		{
			//stats_vendor(fs, stats_req);
		}
		break;

		case OFPT10_PACKET_OUT:
		packet_out(ofph);
		break;

		case OFPT10_FLOW_MOD:
		flow_mod(ofph);
		break;

		case OFPT10_GET_CONFIG_REQUEST:
		config_reply(ofph->xid);
		break;

		case OFPT10_VENDOR:
		vendor_reply(ofph->xid);
		break;

		case OFPT10_BARRIER_REQUEST:
		barrier10_reply(ofph->xid);
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
void features_reply10(uint32_t xid)
{
	uint64_t datapathid = 0;
	int numofports = 0;
	for(int n=0;n<4;n++)
	{
		if(Zodiac_Config.of_port[n]==1)numofports++;
	}
	struct ofp10_switch_features features;
	struct ofp10_phy_port phys_port[numofports];
	uint8_t buf[256];
	int l, k;
	int j = 0;
	char portname[8];

	int bufsize = sizeof(struct ofp10_switch_features) + sizeof(phys_port);
	features.header.version = OF_Version;
	features.header.type = OFPT10_FEATURES_REPLY;
	features.header.length = HTONS(bufsize);
	features.header.xid = xid;
	memcpy(&datapathid, &Zodiac_Config.MAC_address, 6);
	features.datapath_id = datapathid << 16;
	features.n_buffers = htonl(0);		// Number of packets that can be buffered
	features.n_tables = 1;		// Number of flow tables
	features.capabilities = htonl(OFPC10_FLOW_STATS + OFPC10_TABLE_STATS + OFPC10_PORT_STATS);	// Switch Capabilities
	features.actions = htonl((1 << OFPAT10_OUTPUT) + (1 << OFPAT10_SET_VLAN_VID) + (1 << OFPAT10_SET_VLAN_PCP) + (1 << OFPAT10_STRIP_VLAN) + (1 << OFPAT10_SET_DL_SRC) + (1 << OFPAT10_SET_DL_DST) + (1 << OFPAT10_SET_NW_SRC) + (1 << OFPAT10_SET_NW_DST) + (1 << OFPAT10_SET_NW_TOS) + (1 << OFPAT10_SET_TP_SRC) + (1 << OFPAT10_SET_TP_DST));		// Action Capabilities
	uint8_t mac[] = {0x00,0x00,0x00,0x00,0x00,0x00};

	memcpy(&buf, &features, sizeof(struct ofp10_switch_features));
	update_port_status();		//update port status

	for(l = 0; l<TOTAL_PORTS; l++)
	{
		if(Zodiac_Config.of_port[l] == 1)
		{
			phys_port[j].port_no = HTONS(l+1);
			for(k = 0; k<6; k++)            // Generate random MAC address
			{
				int r = rand() % 255;
				memset(mac + k,r,1);
			}
			memcpy(&phys_port[j].hw_addr, mac, sizeof(mac));
			memset(phys_port[j].name, 0, OFP10_MAX_PORT_NAME_LEN);	// Zero out the name string
			sprintf(portname, "eth%d",l);
			strcpy(phys_port[j].name, portname);
			phys_port[j].config = 0;
			phys_port[j].state = htonl(OFPPS10_STP_LISTEN);
			if (port_status[l] == 1) phys_port[j].state = htonl(OFPPS10_STP_LISTEN);
			if (port_status[l] == 0) phys_port[j].state = htonl(OFPPS10_LINK_DOWN);
			phys_port[j].curr = htonl(OFPPF10_100MB_FD + OFPPF10_COPPER);
			phys_port[j].advertised = 0;
			phys_port[j].supported = 0;
			phys_port[j].peer = 0;
			j ++;
		}
	}
	memcpy(&buf[sizeof(struct ofp10_switch_features)], phys_port, sizeof(phys_port));
	sendtcp(&buf, bufsize, 0);
	return;
}

/*
*	OpenFlow SET CONFIG message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void set_config10(struct ofp_header *msg)
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
void config_reply(uint32_t xid)
{
	struct ofp_switch_config cfg_reply;
	cfg_reply.header.version = OF_Version;
	cfg_reply.header.type = OFPT10_GET_CONFIG_REPLY;
	cfg_reply.header.xid = xid;
	cfg_reply.header.length = HTONS(sizeof(cfg_reply));
	cfg_reply.flags = OFPC_FRAG_NORMAL;
	cfg_reply.miss_send_len = 128;		// Send the first 128 bytes of the packet
	sendtcp(&cfg_reply, sizeof(cfg_reply), 1);
	return;
}

/*
*	OpenFlow BARRIER Reply message function
*
*	@param xid - transaction ID
*
*/
void barrier10_reply(uint32_t xid)
{
	struct ofp_header of_barrier;
	of_barrier.version= OF_Version;
	of_barrier.length = htons(sizeof(of_barrier));
	of_barrier.type   = OFPT10_BARRIER_REPLY;
	of_barrier.xid = xid;
	sendtcp(&of_barrier, sizeof(of_barrier), 0);
	return;
}

/*
*	OpenFlow VENDOR Reply message function
*
*	@param xid - transaction ID
*
*/
void vendor_reply(uint32_t xid)
{
	struct ofp_error_msg err_msg;
	err_msg.header.type = OFPT10_ERROR;
	err_msg.header.version = OF_Version;
	err_msg.header.length = HTONS(sizeof(err_msg));
	err_msg.header.xid = xid;
	err_msg.type = htons(OFPET10_BAD_REQUEST);
	err_msg.code = htons(OFPBRC10_BAD_VENDOR);
	sendtcp(&err_msg, sizeof(err_msg), 1);
	return;
}

/*
*	OpenFlow DESCRIPTION Stats Reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void stats10_desc_reply(struct ofp_stats_request *msg)
{
	static struct ofp_desc_stats zodiac_desc = {
		.mfr_desc = "Northbound Networks",
		.hw_desc  = "Zodiac-FX Rev.A",
		.sw_desc  = VERSION,
		.serial_num= "none",
		.dp_desc  = "World's smallest OpenFlow switch!"
	};
	struct ofp10_stats_reply * reply;
	uint16_t len = sizeof(struct ofp10_stats_reply) + sizeof(struct ofp_desc_stats);
	memcpy(shared_buffer, msg, sizeof(*msg));
	reply = (struct ofp10_stats_reply *) shared_buffer;
	reply->header.type = OFPT10_STATS_REPLY;
	reply->header.length = HTONS(len);
	reply->flags = 0;
	memcpy(reply->body, &zodiac_desc, sizeof(zodiac_desc));
	sendtcp(&shared_buffer, len, 1);
	return;
}

/*
*	OpenFlow FLOW Stats Reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void stats_flow_reply(struct ofp_stats_request *msg)
{
	char statsbuffer[2048];
	struct ofp10_stats_reply *reply;
	reply = statsbuffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT10_STATS_REPLY;
	reply->header.xid = msg->header.xid;
	reply->type = htons(OFPST_FLOW);
	int len = flow_stats_msg10(&statsbuffer, 0, iLastFlow);
	reply->header.length = htons(len);
	reply->flags = 0;
	sendtcp(&statsbuffer, len, 0);
	return;
}

/*
*	OpenFlow TABLE Stats Reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void stats_table_reply(struct ofp_stats_request *msg)
{
	struct ofp10_stats_reply reply;
	struct ofp_table_stats tbl_stats;
	int len = sizeof(struct ofp10_stats_reply) + sizeof(struct ofp_table_stats);
	char buf[len];

	reply.header.version = OF_Version;
	reply.header.type = OFPT10_STATS_REPLY;
	reply.header.length = HTONS(len);
	reply.header.xid = msg->header.xid;
	reply.type = HTONS(OFPST_TABLE);
	reply.flags = 0;

	tbl_stats.table_id = 0;
	tbl_stats.max_entries = htonl(MAX_FLOWS_13);
	tbl_stats.active_count = htonl(iLastFlow);
	tbl_stats.lookup_count = htonll(table_counters[0].lookup_count);
	tbl_stats.matched_count = htonll(table_counters[0].matched_count);
	memcpy(buf, &reply, sizeof(struct ofp10_stats_reply));
	memcpy(buf + sizeof(struct ofp10_stats_reply), &tbl_stats, sizeof(struct ofp_table_stats));
	sendtcp(&buf, len, 0);
	return;
}

/*
*	OpenFlow PORT Stats Reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void stats_port_reply(struct ofp_stats_request *msg)
{
	struct ofp10_port_stats zodiac_port_stats;
	struct ofp10_stats_reply reply;
	struct ofp10_port_stats_request *port_req = msg->body;
	int stats_size = 0;
	int len = 0;
	int port = ntohs(port_req->port_no);
	uint8_t * buffer = shared_buffer;	// Local position index

	// Clear shared_buffer
	memset(&shared_buffer, 0, SHARED_BUFFER_LEN);

	if (port == OFPP_NONE)
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
		
		stats_size = (sizeof(struct ofp10_port_stats) * ofports);	// Calculate length of stats
		len = sizeof(struct ofp10_stats_reply) + stats_size;		// Calculate total reply length

		// Format reply header
		reply.header.version = OF_Version;
		reply.header.type = OFPT10_STATS_REPLY;
		reply.header.length = htons(len);
		reply.header.xid = msg->header.xid;
		reply.type = htons(OFPST_PORT);
		reply.flags = 0;

		// Write reply header to buffer
		memcpy(buffer, &reply, sizeof(struct ofp10_stats_reply));
		buffer += sizeof(struct ofp10_stats_reply);

		// Write port stats to reply message
		for(uint8_t k=0; k<TOTAL_PORTS; k++)
		{
			// Check if port is NOT native
			if(!(NativePortMatrix & (1<<(k))))
			{
				zodiac_port_stats.port_no = htons(k+1);
				zodiac_port_stats.rx_packets = htonll(phys10_port_stats[k].rx_packets);
				zodiac_port_stats.tx_packets = htonll(phys10_port_stats[k].tx_packets);
				zodiac_port_stats.rx_bytes = htonll(phys10_port_stats[k].rx_bytes);
				zodiac_port_stats.tx_bytes = htonll(phys10_port_stats[k].tx_bytes);
				zodiac_port_stats.rx_crc_err = htonll(phys10_port_stats[k].rx_crc_err);
				zodiac_port_stats.rx_dropped = htonll(phys10_port_stats[k].rx_dropped);
				zodiac_port_stats.tx_dropped = htonll(phys10_port_stats[k].tx_dropped);
				zodiac_port_stats.rx_frame_err = 0;
				zodiac_port_stats.rx_over_err = 0;
				zodiac_port_stats.tx_errors = 0;
				zodiac_port_stats.rx_errors = 0;
				zodiac_port_stats.collisions = 0;
				
				if((buffer + sizeof(struct ofp10_port_stats)) < (shared_buffer + SHARED_BUFFER_LEN))
				{
					// Write port stats to buffer
					memcpy(buffer, &zodiac_port_stats, sizeof(struct ofp10_port_stats));
					// Increment buffer pointer
					buffer += sizeof(struct ofp10_port_stats);
				}
				else
				{
					TRACE("openflow_10.c: unable to write port stats to shared buffer");
				}
			}
		}
	}
	else if (port > 0 && port <= TOTAL_PORTS)	// Respond to request for ports
	{
		// Check if port is NOT native
		if(!(NativePortMatrix & (1<<(port-1))))
		{
			stats_size = sizeof(struct ofp10_port_stats);
			len = sizeof(struct ofp10_stats_reply) + stats_size;

			reply.header.version = OF_Version;
			reply.header.type = OFPT10_STATS_REPLY;
			reply.header.length = htons(len);
			reply.header.xid = msg->header.xid;
			reply.type = htons(OFPST_PORT);
			reply.flags = 0;

			zodiac_port_stats.port_no = htons(port);
			zodiac_port_stats.rx_packets = htonll(phys10_port_stats[port-1].rx_packets);
			zodiac_port_stats.tx_packets = htonll(phys10_port_stats[port-1].tx_packets);
			zodiac_port_stats.rx_bytes = htonll(phys10_port_stats[port-1].rx_bytes);
			zodiac_port_stats.tx_bytes = htonll(phys10_port_stats[port-1].tx_bytes);
			zodiac_port_stats.rx_crc_err = htonll(phys10_port_stats[port-1].rx_crc_err);
			zodiac_port_stats.rx_dropped = htonll(phys10_port_stats[port-1].rx_dropped);
			zodiac_port_stats.tx_dropped = htonll(phys10_port_stats[port-1].tx_dropped);
			zodiac_port_stats.rx_frame_err = 0;
			zodiac_port_stats.rx_over_err = 0;
			zodiac_port_stats.tx_errors = 0;
			zodiac_port_stats.rx_errors = 0;
			zodiac_port_stats.collisions = 0;

			memcpy(shared_buffer, &reply, sizeof(struct ofp10_stats_reply));
			memcpy(shared_buffer + sizeof(struct ofp10_stats_reply), &zodiac_port_stats, stats_size);
		}
		else
		{
			TRACE("openflow_10.c: requested port is out of range");
			of10_error(buffer, OFPET10_BAD_REQUEST, OFPBRC10_BAD_STAT);
		}
	}
	else
	{
		TRACE("openflow_10.c: requested port is out of range");
		of10_error(buffer, OFPET10_BAD_REQUEST, OFPBRC10_BAD_STAT);
	}
	sendtcp(&shared_buffer, len, 0);
	return;
}

/*
*	OpenFlow PACKET_OUT function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void packet_out(struct ofp_header *msg)
{
	struct ofp_packet_out * po;
	po = (struct ofp_packet_out *) msg;
	uint8_t * ptr = (uint8_t *) po;
	uint16_t *iport;
	iport = ptr + 12;
	ptr += sizeof(struct ofp_packet_out) + NTOHS(po->actions_len);
	int size = NTOHS(po->header.length) - ((sizeof(struct ofp_packet_out) + NTOHS(po->actions_len)));
	uint16_t *eport;
	eport = ptr - 4;
	int outPort = NTOHS(*eport);
	int inPort = NTOHS(*iport);

	if (outPort == OFPP_TABLE)
	{
		nnOF_tablelookup(ptr, &size, inPort);
		return;
	}

	if (outPort == OFPP_FLOOD || outPort == OFPP13_ALL)
	{
		outPort = (15 - NativePortMatrix) - (1<<(inPort-1));
	} else
	{
		outPort = 1 << (outPort-1);
	}
	gmac_write(ptr, size, outPort);
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
void packet_in(uint8_t *buffer, uint16_t ul_size, uint32_t port, uint8_t reason)
{
	uint16_t send_size = ul_size;
	if(tcp_sndbuf(tcp_pcb) < (send_size + 18)) return;
	uint16_t size = 0;
	struct ofp_packet_in * pi;

	size = send_size + 18;
	memset(shared_buffer, 0, 128);
	pi = (struct ofp_packet_in *) shared_buffer;
	pi->header.version = OF_Version;
	pi->header.type = OFPT10_PACKET_IN;
	pi->header.xid = 0;
	pi->buffer_id = -1;
	pi->in_port = HTONS(port);
	pi->header.length = HTONS(size);
	pi->total_len = HTONS(ul_size);
	pi->reason = reason;
	memcpy(pi->data, buffer, send_size);
	sendtcp(&shared_buffer, size, 1);
	return;
}

/*
*	Main OpenFlow FLOW_MOD message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_mod(struct ofp_header *msg)
{
	///**/TRACE("____________________ FLOWMOD ENTRY");
	struct ofp_flow_mod * ptr_fm;
	ptr_fm = (struct ofp_flow_mod *) msg;

	uint8_t command = HTONS(ptr_fm->command);
	switch(command)
	{

		case OFPFC_ADD:
		///**/TRACE("____________________ ADD");
		flow_add(msg);
		break;

		case OFPFC_MODIFY:
		flow_modify(msg);
		break;

		case OFPFC_MODIFY_STRICT:
		flow_modify_strict(msg);
		break;

		case OFPFC_DELETE:
		flow_delete(msg);
		break;

		case OFPFC_DELETE_STRICT:
		flow_delete_strict(msg);
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
void flow_add(struct ofp_header *msg)
{

	if (iLastFlow > (MAX_FLOWS_10-1))
	{
		of10_error(msg, OFPET10_FLOW_MOD_FAILED, OFPFMFC10_ALL_TABLES_FULL);
		return;
	}

	struct ofp_flow_mod * ptr_fm;
	ptr_fm = (struct ofp_flow_mod *) msg;
	struct ofp_action_header * action_hdr = NULL;
	struct ofp_action_header * action_hdr1 = NULL;
	int action_size = ntohs(msg->length) - sizeof(struct ofp_flow_mod);
	int action_cnt_size = 0;
	int action_count = 0;

	action_hdr = &ptr_fm->actions;
	
	flow_match10[iLastFlow] = membag_alloc(sizeof(struct ofp_flow_mod));	// Allocate a space to store match fields
	flow_actions10[iLastFlow] = membag_alloc(sizeof(struct flow_tbl_actions));	// Allocate a space to store actions fields
	if (flow_match10[iLastFlow] == NULL || flow_actions10[iLastFlow] == NULL)
	{
		TRACE("Unable to allocate %d bytes of memory for match fields", sizeof(struct ofp_flow_mod));
		of10_error(msg, OFPET10_FLOW_MOD_FAILED, OFPFMFC10_ALL_TABLES_FULL);
		return;
	}
	TRACE("Allocating %d bytes at %p for flow %d", sizeof(struct ofp_flow_mod), flow_match10[iLastFlow], iLastFlow+1);
	
	memcpy(flow_match10[iLastFlow], ptr_fm, sizeof(struct ofp_flow_mod));

	if(action_size > 0)
	{
		for(int q=0;q<4;q++)
		{
			if (action_cnt_size < action_size)
			{
				action_hdr1 = action_hdr + action_count;

				// Check for unsupported ports
				if (HTONS(action_hdr1->type) == OFPAT10_OUTPUT)
				{
					struct ofp_action_output * action_out;
					action_out = action_hdr1;

					if (htons(action_out->port) == OFPP_NORMAL) // We do not support port NORMAL
					{
						of10_error(msg, OFPET10_BAD_ACTION, OFPBAC10_BAD_OUT_PORT);
						return;
					}
				}
				// If set VLAD ID field is 0 change to a STRIP_VLAN action
				if (htons(action_hdr1->type) == OFPAT10_SET_VLAN_VID)
				{
					struct ofp_action_vlan_vid * action_vlan;
					action_vlan = action_hdr1;
					if(action_vlan->vlan_vid == 0) action_hdr1->type = htons(OFPAT10_STRIP_VLAN);
				}

				// Copy action
				if(q == 0) memcpy(flow_actions10[iLastFlow]->action1, action_hdr1, ntohs(action_hdr1->len));
				if(q == 1) memcpy(flow_actions10[iLastFlow]->action2, action_hdr1, ntohs(action_hdr1->len));
				if(q == 2) memcpy(flow_actions10[iLastFlow]->action3, action_hdr1, ntohs(action_hdr1->len));
				if(q == 3) memcpy(flow_actions10[iLastFlow]->action4, action_hdr1, ntohs(action_hdr1->len));
			}
			if(ntohs(action_hdr1->len) == 8) action_count += 1;
			if(ntohs(action_hdr1->len) == 16) action_count += 2;
			action_cnt_size += ntohs(action_hdr1->len);
		}
	}

	flow_counters[iLastFlow].duration = (totaltime/2);
	flow_counters[iLastFlow].lastmatch = (totaltime/2);
	flow_counters[iLastFlow].active = true;
	iLastFlow++;
	return;

}

/*
*	OpenFlow FLOW Modify function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_modify(struct ofp_header *msg)
{
	struct ofp_flow_mod * ptr_fm;
	ptr_fm = (struct ofp_flow_mod *) msg;
	struct ofp_action_header * action_hdr = NULL;
	struct ofp_action_header * action_hdr1 = NULL;
	int action_size = ntohs(msg->length) - sizeof(struct ofp_flow_mod);
	int action_cnt_size = 0;
	int action_count = 0;
	int matched = 0;

	for(int q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if (field_match10(&ptr_fm->match, &flow_match10[q]->match) == 1)
			{
				matched = 1;
				// Update actions
				action_hdr = &ptr_fm->actions;
				if(action_size > 0)
				{
					for(int j=0;j<4;j++)
					{
						if (action_cnt_size < action_size)
						{
							action_hdr1 = action_hdr + action_count;

							// Check for unsupported ports
							if (HTONS(action_hdr1->type) == OFPAT10_OUTPUT)
							{
								struct ofp_action_output * action_out;
								action_out = action_hdr1;

								if (htons(action_out->port) == OFPP_NORMAL) // We do not support port NORMAL
								{
									of10_error(msg, OFPET10_BAD_ACTION, OFPBAC10_BAD_OUT_PORT);
									return;
								}
							}
							// If set VLAD ID field is 0 change to a STRIP_VLAN action
							if (htons(action_hdr1->type) == OFPAT10_SET_VLAN_VID)
							{
								struct ofp_action_vlan_vid * action_vlan;
								action_vlan = action_hdr1;
								if(action_vlan->vlan_vid == 0) action_hdr1->type = htons(OFPAT10_STRIP_VLAN);
							}

							// Copy actions
							if(j == 0) memcpy(flow_actions10[q]->action1, action_hdr1, ntohs(action_hdr1->len));
							if(j == 1) memcpy(flow_actions10[q]->action2, action_hdr1, ntohs(action_hdr1->len));
							if(j == 2) memcpy(flow_actions10[q]->action3, action_hdr1, ntohs(action_hdr1->len));
							if(j == 3) memcpy(flow_actions10[q]->action4, action_hdr1, ntohs(action_hdr1->len));
						}
						if(ntohs(action_hdr1->len) == 8) action_count += 1;
						if(ntohs(action_hdr1->len) == 16) action_count += 2;
						action_cnt_size += ntohs(action_hdr1->len);
					}
				}
			}
		}
	}
	// If there is no existing flow that matches then it's just an ADD
	if (matched == 1)
	{
		flow_add(msg);
	}

	return;
}

/*
*	OpenFlow FLOW Modify Strict function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_modify_strict(struct ofp_header *msg)
{
	struct ofp_flow_mod * ptr_fm;
	ptr_fm = (struct ofp_flow_mod *) msg;
	struct ofp_action_header * action_hdr = NULL;
	struct ofp_action_header * action_hdr1 = NULL;
	int action_size = ntohs(msg->length) - sizeof(struct ofp_flow_mod);
	int action_cnt_size = 0;
	int action_count = 0;
	int matched = 0;

	for(int q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if((memcmp(&flow_match10[q]->match, &ptr_fm->match, sizeof(struct ofp_match)) == 0) && (flow_match10[q]->priority == ptr_fm->priority))
			{
				matched = 1;
				// Update actions
				action_hdr = &ptr_fm->actions;
				if(action_size > 0)
				{
					for(int j=0;j<4;j++)
					{
						if (action_cnt_size < action_size)
						{
							action_hdr1 = action_hdr + action_count;

							// Check for unsupported ports
							if (HTONS(action_hdr1->type) == OFPAT10_OUTPUT)
							{
								struct ofp_action_output * action_out;
								action_out = action_hdr1;

								if (htons(action_out->port) == OFPP_NORMAL) // We do not support port NORMAL
								{
									of10_error(msg, OFPET10_BAD_ACTION, OFPBAC10_BAD_OUT_PORT);
									return;
								}
							}
							// If set VLAD ID field is 0 change to a STRIP_VLAN action
							if (htons(action_hdr1->type) == OFPAT10_SET_VLAN_VID)
							{
								struct ofp_action_vlan_vid * action_vlan;
								action_vlan = action_hdr1;
								if(action_vlan->vlan_vid == 0) action_hdr1->type = htons(OFPAT10_STRIP_VLAN);
							}

							// Copy actions
							if(j == 0) memcpy(flow_actions10[q]->action1, action_hdr1, ntohs(action_hdr1->len));
							if(j == 1) memcpy(flow_actions10[q]->action2, action_hdr1, ntohs(action_hdr1->len));
							if(j == 2) memcpy(flow_actions10[q]->action3, action_hdr1, ntohs(action_hdr1->len));
							if(j == 3) memcpy(flow_actions10[q]->action4, action_hdr1, ntohs(action_hdr1->len));
						}
						if(ntohs(action_hdr1->len) == 8) action_count += 1;
						if(ntohs(action_hdr1->len) == 16) action_count += 2;
						action_cnt_size += ntohs(action_hdr1->len);
					}
				}
			}
		}
	}
	// If there is no existing flow that matches then it's just an ADD
	if (matched == 1)
	{
		flow_add(msg);
	}
	return;
}

/*
*	OpenFlow FLOW Delete function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_delete(struct ofp_header *msg)
{
	struct ofp_flow_mod * ptr_fm;
	ptr_fm = (struct ofp_flow_mod *) msg;
	int q = 0;

	while(q<iLastFlow)
	{
		if(flow_counters[q].active == true)
		{
			if (field_match10(&ptr_fm->match, &flow_match10[q]->match) == 1)
			{
				if (ptr_fm->flags &  OFPFF10_SEND_FLOW_REM) flowrem_notif10(q,OFPRR10_DELETE);
				// Clear flow counters and actions
				memset(&flow_counters[q], 0, sizeof(struct flows_counter));
				memset(flow_actions10[q], 0, sizeof(struct flow_tbl_actions));
				// Copy the last flow to here to fill the gap
				memcpy(flow_match10[q], flow_match10[iLastFlow-1], sizeof(struct ofp_flow_mod));
				memcpy(flow_actions10[q], &flow_actions10[iLastFlow-1], sizeof(struct flow_tbl_actions));
				memcpy(&flow_counters[q], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
				// Clear the counters and action from the last flow that was moved
				memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
				memset(flow_actions10[iLastFlow-1], 0, sizeof(struct flow_tbl_actions));
				iLastFlow --;
				} else {
				q++;
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
void flow_delete_strict(struct ofp_header *msg)
{
	struct ofp_flow_mod * ptr_fm;
	ptr_fm = (struct ofp_flow_mod *) msg;
	int q;

	for(q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if((memcmp(&flow_match10[q]->match, &ptr_fm->match, sizeof(struct ofp_match)) == 0) && (memcmp(&flow_match10[q]->cookie, &ptr_fm->cookie,8) == 0))
			{
				if (ptr_fm->flags &  OFPFF10_SEND_FLOW_REM) flowrem_notif10(q,OFPRR10_DELETE);
				remove_flow10(q);
			}
		}
	}
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
void of10_error(struct ofp_header *msg, uint16_t type, uint16_t code)
{
	// get the size of the message, we send up to the first 64 back with the error
	int msglen = htons(msg->length);
	if (msglen > 64) msglen = 64;
	char error_buf[96];
	struct ofp_error_msg error;
	error.header.type = OFPT10_ERROR;
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
void flowrem_notif10(int flowid, uint8_t reason)
{
	struct ofp_flow_removed ofr;
	double diff;

	ofr.header.type = OFPT10_FLOW_REMOVED;
	ofr.header.version = OF_Version;
	ofr.header.length = htons(sizeof(struct ofp_flow_removed));
	ofr.header.xid = 0;
	ofr.cookie = flow_match10[flowid]->cookie;
	ofr.reason = reason;
	ofr.priority = flow_match10[flowid]->priority;
	diff = (totaltime/2) - flow_counters[flowid].duration;
	ofr.duration_sec = htonl(diff);
	ofr.packet_count = flow_counters[flowid].hitCount;
	ofr.byte_count = flow_counters[flowid].bytes;
	ofr.idle_timeout = flow_match10[flowid]->idle_timeout;
	ofr.match = flow_match10[flowid]->match;
	sendtcp(&ofr, sizeof(struct ofp_flow_removed), 1);
	return;
}

/*
*	OpenFlow Port Status message function
*
*	@param port - port number that has changed.
*
*/
void port_status_message10(uint8_t port)
{
	char portname[8];
	uint8_t mac[] = {0x00,0x00,0x00,0x00,0x00,0x00};
	struct ofp_port_status ofps;
	
	ofps.header.type = OFPT10_PORT_STATUS;
	ofps.header.version = OF_Version;
	ofps.header.length = htons(sizeof(struct ofp_port_status));
	ofps.header.xid = 0;
	ofps.reason = OFPPR10_MODIFY;
	ofps.desc.port_no = htons(port+1);
	for(int k = 0; k<6; k++)            // Generate random MAC address
	{
		int r = rand() % 255;
		memset(mac + k,r,1);
	}
	memcpy(&ofps.desc.hw_addr, mac, sizeof(mac));
	memset(ofps.desc.name, 0, OFP10_MAX_PORT_NAME_LEN);	// Zero out the name string
	sprintf(portname, "eth%d",port);
	strcpy(ofps.desc.name, portname);
	ofps.desc.config = 0;
	if (port_status[port] == 1) ofps.desc.state = htonl(OFPPS10_STP_LISTEN);
	if (port_status[port] == 0) ofps.desc.state = htonl(OFPPS10_LINK_DOWN);
	ofps.desc.curr = htonl(OFPPF10_100MB_FD + OFPPF10_COPPER);
	ofps.desc.advertised = 0;
	ofps.desc.supported = 0;
	ofps.desc.peer = 0;
	sendtcp(&ofps, htons(ofps.header.length), 1);
	TRACE("openflow_10.c: Port Status change notification sent");
	return;
}
