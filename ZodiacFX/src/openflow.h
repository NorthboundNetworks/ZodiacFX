/**
 * @file
 * openflow.h
 *
 * This file contains the function declarations and structures for the OpenFlow functions
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

#ifndef OPENFLOW_H_
#define OPENFLOW_H_

#include "openflow_spec/openflow_spec10.h"
#include "openflow_spec/openflow_spec13.h"
#include "of_helper.h"
#include <lwip/err.h>
#include <lwip/tcp.h>

struct flows_counter
{
	int hitCount;
	int bytes;
	int duration;
	int active;
	int lastmatch;
};

struct table_counter
{
	int lookup_count;
	int matched_count;
};

struct flow_tbl_actions
{
	uint8_t action1[16];
	uint8_t action2[16];
	uint8_t action3[16];
	uint8_t action4[16];
};

struct oxm_header13
{
	uint16_t oxm_class;
	uint8_t oxm_field;
	uint8_t oxm_len;
};


void task_openflow(void);
void nnOF_tablelookup(char *p_uc_data, uint32_t *ul_size, int port);
void nnOF10_tablelookup(char *p_uc_data, uint32_t *ul_size, int port);
void nnOF13_tablelookup(char *p_uc_data, uint32_t *ul_size, int port);
void of10_message(struct ofp_header *ofph, int size, int len);
void of13_message(struct ofp_header *ofph, int size, int len);
void barrier10_reply(uint32_t xid);
void barrier13_reply(uint32_t xid);
void sendtcp(const void *buffer, u16_t len);
void flowrem_notif(int flowid, uint8_t reason);
	
#define HTONS(x) ((((x) & 0xff) << 8) | (((x) & 0xff00) >> 8))
#define NTOHS(x) HTONS(x)
#define HTONL(x) ((((x) & 0xff) << 24) | \
(((x) & 0xff00) << 8) | \
(((x) & 0xff0000UL) >> 8) | \
(((x) & 0xff000000UL) >> 24))
#define NTOHL(x) HTONL(x)


/* ---- kwi0 version ---- */

struct flows_counter reset_counter();

/* ---- kwi version ---- */

#define ALIGN8(x) (x+7)/8*8

enum ofp_pcb_status {
	OFP_OK, // successfully processed
	OFP_NOOP, // precondition not satisfied
	OFP_CLOSE, // connection closed
};

#define RECV_BUFLEN 4096U
#define MP_UNIT_MAXSIZE 512U

struct ofp_pcb {
	struct tcp_pcb *tcp;
	struct pbuf *rbuf; // controller may send very long message
	int rskip;
	uint32_t txlen;
	bool negotiated;
	bool mpreq_on; // processing multipart
	uint16_t mpreq_pos; // multipart processing position.
	char mpreq_hdr[16]; // multipart request data header
	char mp_in[MP_UNIT_MAXSIZE]; // table_features would be the largest
	int mp_out_index; // output index
	uint32_t xid;
	uint32_t sleep_until;
	uint32_t alive_until;
	uint32_t next_ping;
};

#define OFP_BUFFER_LEN 2048

#define MAX_CONTROLLERS 2

struct controller {
	struct ip_addr addr;
	struct ofp_pcb ofp;
};

void openflow_init(void);
void openflow_task(void);
void openflow_pipeline(struct pbuf*, uint32_t);
uint16_t ofp_rx_length(struct ofp_pcb*);
uint16_t ofp_rx_read(struct ofp_pcb*, void*, uint16_t);
uint16_t ofp_tx_room(struct ofp_pcb*);
uint16_t ofp_tx_write(struct ofp_pcb*, const void*, uint16_t);
uint16_t ofp_set_error(const char*, uint16_t, uint16_t);

uint16_t mod_ofp13_flow(struct ofp13_flow_mod*);

int field_match13(const char*, int, const char*, int);

struct fx_switch_config {
	uint16_t flags;
	uint16_t miss_send_len;
};

struct fx_table_count {
	uint64_t lookup;
	uint64_t matched;
};
#define MAX_TABLES 10 // must be smaller than OFPTT13_MAX

struct fx_packet { // in network byte order
	struct pbuf *data;
	// pipeline fields
	uint32_t in_port;
	uint64_t metadata;
	uint64_t tunnel_id;
	uint32_t in_phy_port;
};
struct fx_packet_oob { // in network byte order
	// cache
	uint16_t vlan;
	uint16_t eth_type;
	uint16_t eth_offset;
	// pipeline
	uint16_t action_set_oxm_length; // in host byte order
	const char* action_set_oxm; // malloc-ed oxm
	const char* action_set[16]; // just reference to ofp_action inside fx_flow.ops
};
struct fx_packet_in { // in network byte order
	uint8_t send_bits; // controller bitmap supporting up to 7 controllers now. 0x80 is for packet_out
	uint32_t valid_until; // sys_ms (in host network byte order)
	uint32_t buffer_id;
	uint8_t reason;
	uint8_t table_id;
	uint64_t cookie;
	struct fx_packet packet;
	uint16_t max_len; // in host byte order
};
#define MAX_BUFFERS 16
#define BUFFER_TIMEOUT 5000U /* ms */
struct fx_packet_oob create_oob(struct pbuf*);

struct fx_flow {
	uint8_t send_bits; // 0=init, 0x80=active, 0x01=prepared to send_flow_rem to controller[0].
	uint8_t table_id;
	uint16_t priority;
	uint16_t flags;
	uint16_t oxm_length;
	uint16_t ops_length;
	const char* oxm;
	const char* ops; // openflow 1.0 actions or openflow 1.3 instructions
	struct ofp_match tuple; // openflow 1.0 12-tuple
	uint64_t cookie;
};
struct fx_flow_timeout {
	uint16_t idle_timeout; // config duration
	uint16_t hard_timeout; // config duration
	uint32_t init; // system clock time (ms)
	uint32_t update; // system clock time (ms)
	// Using system clock (ms) here is ok because
	// UINT16_MAX sec is about 18 hours and
	// UINT32_MAX ms is about 1193 hours.
	// We can track the wrap-around.
};
struct fx_flow_count {
	uint64_t packet_count;
	uint64_t byte_count;
};
#define FX_FLOW_ACTIVE 0x80

int match_frame_by_oxm(struct fx_packet, struct fx_packet_oob, const char*, uint16_t);
int match_frame_by_tuple(struct fx_packet, struct fx_packet_oob, struct ofp_match);
void execute_ofp13_flow(struct fx_packet*, struct fx_packet_oob*, int flow);
void execute_ofp10_flow(struct fx_packet*, struct fx_packet_oob*, int flow);

enum ofp_pcb_status ofp13_multipart_complete(struct ofp_pcb*);
enum ofp_pcb_status ofp13_handle(struct ofp_pcb*);

#endif /* OPENFLOW_H_ */