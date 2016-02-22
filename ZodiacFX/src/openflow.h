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

#pragma once

#include "openflow_spec/openflow_spec10.h"
#include "openflow_spec/openflow_spec13.h"
#include "of_helper.h"
#include <lwip/err.h>
#include <lwip/tcp.h>

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
uint16_t ofp_rx_length(const struct ofp_pcb*);
uint16_t ofp_rx_read(struct ofp_pcb*, void*, uint16_t);
uint16_t ofp_tx_room(const struct ofp_pcb*);
uint16_t ofp_tx_write(struct ofp_pcb*, const void*, uint16_t);
uint16_t ofp_set_error(const void*, uint16_t, uint16_t);

int field_match13(const void*, int, const void*, int);

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
	void *action_set_oxm; // malloc-ed oxm
	void *action_set[16]; // just reference to ofp_action inside fx_flow.ops
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
void create_oob(struct pbuf*, struct fx_packet_oob*);

// in host byte order
struct fx_flow {
	uint8_t send_bits; // 0=init, 0x80=active, 0x01=prepared to send_flow_rem to controller[0].
	uint8_t table_id;
	uint16_t priority;
	uint16_t flags;
	uint16_t oxm_length;
	uint16_t ops_length;
	void *oxm;
	void *ops; // openflow 1.0 actions or openflow 1.3 instructions
	struct ofp_match tuple; // openflow 1.0 12-tuple
	uint64_t cookie;
	uint8_t reason; // set only if send_flow_rem required
};
struct fx_flow_timeout { // in host byte order
	uint16_t idle_timeout; // config duration
	uint16_t hard_timeout; // config duration
	uint32_t update; // system clock time (ms)
	uint64_t init; // system clock time (ms)
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

struct fx_port {
	uint8_t send_bits; // for OFPPR_ADD, OFPPR_DELETE
	uint8_t send_bits_mod; // for OFPPR_MODIFY
	uint16_t state; // OFPPS_
	uint16_t config; // OFPPC_
	uint64_t init; // sys_ms; update on config change
};
struct fx_port_count {
	uint64_t rx_packets;
	uint64_t tx_packets;
	uint64_t rx_bytes; // sw
	uint64_t tx_bytes; // sw
	uint64_t rx_dropped; // sw
	uint64_t tx_dropped; // sw
	uint64_t rx_errors; // sw
	uint64_t tx_errors; // sw
	uint64_t rx_frame_err; // sw
	uint64_t rx_over_err; // sw
	uint64_t rx_crc_err; // sw
	uint64_t collisions; // sw
};
#define MAX_PORTS 4

// in host byte order
struct fx_meter {
	uint32_t meter_id; // in network byte order
	uint16_t flags;
};
// in host byte order
struct fx_meter_band {
	uint32_t meter_id; // in network byte order
	uint16_t type;
	uint32_t rate;
	uint32_t burst_size;
	uint8_t prec_level;
};
#define MAX_METERS 0
#define MAX_METER_BANDS 0

// in host byte order
struct fx_group {
	uint32_t group_id; // in network byte order
	uint8_t type;
};
// in host byte order
struct fx_group_bucket {
	uint32_t group_id; // in network byte order
	uint16_t weight;
	uint32_t watch_port;
	uint32_t watch_group;
	uint16_t actions_len;
	void *actions;
};
#define MAX_GROUPS 0
#define MAX_GROUP_BUCKETS 0

// openflow message handling
enum ofp_pcb_status ofp13_multipart_complete(struct ofp_pcb*);
enum ofp_pcb_status ofp13_handle(struct ofp_pcb*);

// flow processing
int lookup_fx_table(const struct fx_packet*, const struct fx_packet_oob*, uint8_t);
int match_frame_by_oxm(const struct fx_packet*, const struct fx_packet_oob*, const void*, uint16_t);
int match_frame_by_tuple(const struct fx_packet*, const struct fx_packet_oob*, struct ofp_match);
void execute_ofp13_flow(struct fx_packet*, struct fx_packet_oob*, int flow);
void execute_ofp10_flow(struct fx_packet*, struct fx_packet_oob*, int flow);

// async
void send_ofp13_port_status(void);
void send_ofp13_flow_rem(void);
void timeout_ofp13_flows(void);
void check_ofp13_packet_in(void);
