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

void openflow_init(void);
void openflow_task(void);
uint16_t ofp_rx_length(struct ofp_pcb*);
uint16_t ofp_rx_read(struct ofp_pcb*, char*, uint16_t);
uint16_t ofp_tx_room(struct ofp_pcb*);
uint16_t ofp_rx_write(struct ofp_pcb*, char*, uint16_t);
uint16_t ofp_set_error(const char*, uint16_t, uint16_t);

uint16_t mod_ofp13_flow(struct ofp13_flow_mod*);

bool field_cmp13(const char*, int, const char*, int);
int field_match13(const char*, int, const char*, int);

enum ofp_pcb_status ofp13_handle(struct ofp_pcb *self);
enum ofp_pcb_status ofp10_handle(struct ofp_pcb *self);

#endif /* OPENFLOW_H_ */