/**
 * @file
 * openflow.c
 *
 * This file contains the main OpenFlow functions
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
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "timers.h"

// Global variables
extern struct zodiac_config Zodiac_Config;
extern uint8_t port_status[4];
extern struct ofp10_port_stats phys10_port_stats[4];
extern struct ofp13_port_stats phys13_port_stats[4];

// Local Variables
struct ofp_switch_config Switch_config;
struct ofp_flow_mod flow_match[MAX_FLOWS];
struct ofp13_flow_mod flow_match13[MAX_FLOWS];
uint8_t *ofp13_oxm_match[MAX_FLOWS];
uint8_t *ofp13_oxm_inst[MAX_FLOWS];
uint16_t ofp13_oxm_inst_size[MAX_FLOWS];
struct flows_counter flow_counters[MAX_FLOWS];
struct flow_tbl_actions flow_actions[MAX_FLOWS];
struct table_counter table_counters[MAX_TABLES];
int iLastFlow = 0;
uint8_t shared_buffer[2048];
char sysbuf[64];
struct ip_addr serverIP;
int OF_Version = 0x00;
struct tcp_pcb *tcp_pcb;
struct tcp_pcb *tcp_pcb_check;
int fast_of_timer = 0;
int tcp_con_state = -1;
int tcp_wait = 0;
int delay_barrier;
uint32_t barrier_xid;
int totaltime = 0;
int heartbeat = 0;
int multi_pos;
bool rcv_freq;

// Internal Functions
void OF_hello(void);
void echo_request(void);
void echo_reply(uint32_t xid);
err_t TCPready(void *arg, struct tcp_pcb *tpcb, err_t err);
void tcp_error(void * arg, err_t err);
static err_t of_receive(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);

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

void nnOF_tablelookup(uint8_t *p_uc_data, uint32_t *ul_size, int port)
{
	if( tcp_pcb != tcp_pcb_check)	// Check if the connect pointer is still valid
	{
		tcp_con_state = -1;
		tcp_pcb = NULL;
		return;
	}

	if (Zodiac_Config.failstate == 0 && tcp_pcb->state != ESTABLISHED) return;	// If the controller is not connected and fail secure is enabled drop the packet

	if (OF_Version == 0x01) nnOF10_tablelookup(p_uc_data, ul_size, port);
	if (OF_Version == 0x04) nnOF13_tablelookup(p_uc_data, ul_size, port);
	return;
}

/*
*	Main OpenFlow message function
*
*	@param *arg - pointer the additional TCP args
*	@param *tcp_pcb - pointer the TCP session structure.
*	@param *p - pointer to the buffer containing the TCP packet.
*	@param err - error code.
*
*/
static err_t of_receive(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	char *pc;
	char packetbuffer[1536];
	heartbeat = 0;	// Reset heartbeat counter

	if (err == ERR_OK && p != NULL)
	{
		tcp_recved(tpcb, p->tot_len);
        pc=(char *)p->payload;	//pointer to the payload
        int len = p->tot_len;	//size of the payload
        for (int i=0; i<len; i++)packetbuffer[i] = pc[i];	//copy to our own buffer
        pbuf_free(p);	//Free the packet buffer
		TRACE("OpenFlow data received (%d bytes)", len);
		struct ofp_header *ofph;
		int size = 0;
		int plen = 0;

		while (size < len)
		{
			ofph = &packetbuffer[size];
			if (size == 0) multi_pos = 0;
			if (ofph->length == 0 || ofph->version == 0){
				return ERR_OK;	//Not an OpenFlow packet
			}
			plen = htons(ofph->length);
			size = size + plen;
			TRACE("Processing %d byte OpenFlow message %u (%d)", plen, htonl(ofph->xid), size);

			switch(ofph->type)
			{
				case OFPT10_HELLO:
				if (ofph->version == Zodiac_Config.of_version)
				{
					OF_Version = Zodiac_Config.of_version;
				} else if (ofph->version > MAX_OFP_VERSION && Zodiac_Config.of_version == 0) {
					OF_Version = MAX_OFP_VERSION;
				} else if (ofph->version == 1 && Zodiac_Config.of_version == 0) {
					OF_Version = 0x01;
				} else if (ofph->version == 4 && Zodiac_Config.of_version == 0) {
					OF_Version = 0x04;
				} else if (Zodiac_Config.of_version != 0) {
					OF_Version = Zodiac_Config.of_version;
				}

				break;

				case OFPT10_ECHO_REQUEST:
					echo_reply(ofph->xid);
				break;

				default:
					if (OF_Version == 0x01) of10_message(ofph, size, len);
					if (OF_Version == 0x04) of13_message(ofph, size, len);
			};

		}
	} else {
		pbuf_free(p);
	}

	if ((err = ERR_OK) && (p == NULL))
	{
		tcp_close(tpcb);
	}
	return ERR_OK;
}

/*
*	OpenFlow HELLO message function
*
*/
void OF_hello(void)
{
	struct ofp_header ofph;
	OF_Version = 0x00;
	rcv_freq = false;
	// Make sure this is a valid version otherwise it won't connect
	if (Zodiac_Config.of_version == 1){
		ofph.version = 1;
	} else if (Zodiac_Config.of_version == 4){
		ofph.version = 4;
	} else {
		ofph.version = MAX_OFP_VERSION;
	}
	ofph.type = OFPT10_HELLO;
	ofph.length = HTONS(sizeof(ofph));
	ofph.xid = HTONL(1);
	sendtcp(&ofph, sizeof(ofph));
	TRACE("Sent HELLO, version 0x%d", ofph.version);
	return;
}

/*
*	OpenFlow ECHO Reply message function
*
*	@param xid - transaction ID
*
*/
void echo_reply(uint32_t xid)
{
	struct ofp_header echo;
	echo.version = OF_Version;
	echo.length = HTONS(sizeof(echo));
	echo.type   = OFPT10_ECHO_REPLY;
	echo.xid = xid;
	sendtcp(&echo, sizeof(echo));
	TRACE("Sent ECHO reply");
	return;
}

/*
*	OpenFlow ECHO Request message function
*
*/
void echo_request(void)
{
	struct ofp_header echo;
	echo.version= OF_Version;
	echo.length = HTONS(sizeof(echo));
	echo.type   = OFPT10_ECHO_REQUEST;
	echo.xid = 1234;
	sendtcp(&echo, sizeof(echo));
	TRACE("Sent ECHO request");
	return;
}

/*
*	TCP send packet function
*
*	@param *buffer - pointer to the buffer containing the data to send.
*	@param len - size of the packet to send
*
*/
void sendtcp(const void *buffer, u16_t len)
{
	err_t err;
	if( tcp_pcb != tcp_pcb_check)
	{
		tcp_con_state = -1;
		tcp_pcb = NULL;
		return;
	}
	err = tcp_write(tcp_pcb, buffer, len, TCP_WRITE_FLAG_COPY);
	if (err == ERR_OK) tcp_output(tcp_pcb);
	return;
}

/*
*	Main OpenFlow processing loop
*
*/
void task_openflow(void)
{
	if (delay_barrier == 1) {
		if (OF_Version == 0x01) barrier10_reply(barrier_xid);
		if (OF_Version == 0x04) barrier13_reply(barrier_xid);
		delay_barrier = 0;
	}

	if (tcp_con_state == 0 && Zodiac_Config.OFEnabled == OF_ENABLED)
	{
		tcp_con_state = 1;
		IP4_ADDR(&serverIP, Zodiac_Config.OFIP_address[0], Zodiac_Config.OFIP_address[1], Zodiac_Config.OFIP_address[2], Zodiac_Config.OFIP_address[3]);
		tcp_pcb = tcp_new();
		tcp_pcb_check = tcp_pcb;
		tcp_arg(tcp_pcb, NULL);
		tcp_err(tcp_pcb, tcp_error);
		tcp_nagle_disable(tcp_pcb);
		tcp_connect(tcp_pcb, &serverIP, Zodiac_Config.OFPort, TCPready);
		return;
	}

	if(tcp_pcb == tcp_pcb_check)
	{
		if (tcp_con_state == 1 && tcp_pcb->state != ESTABLISHED && Zodiac_Config.OFEnabled == OF_ENABLED)
		{
			tcp_con_state = -1;
			if(Zodiac_Config.failstate == 0) clear_flows();		// Clear the flow if in secure mode
		}

		if (tcp_con_state == 1 && tcp_pcb->state == ESTABLISHED && Zodiac_Config.OFEnabled == OF_DISABLED)
		{
			tcp_con_state = -1;
			if(Zodiac_Config.failstate == 0) clear_flows();		// Clear the flow if in secure mode
			tcp_close(tcp_pcb);
		}
	} else {
		tcp_con_state = -1;
		tcp_pcb = NULL;
	}


	if((sys_get_ms() - fast_of_timer) > 500)	// every 500 ms (0.5 secs)
	{
		fast_of_timer = sys_get_ms();
		nnOF_timer();

		if (heartbeat > (HB_INTERVAL * 2) && tcp_con_state == 1)	//If we haven't heard anything from the controller for more then the heartbeat interval send an echo request
		{
			if (rcv_freq == false)	// If we never got a feature request then the handshake failed, disconnect and try again.
			{
				tcp_con_state = -1;
				if(Zodiac_Config.failstate == 0) clear_flows();		// Clear the flow if in secure mode
				tcp_close(tcp_pcb);
			} else {
				echo_request();
			}
		}
		heartbeat++;	// Increment number of seconds since last response
		if (heartbeat > (HB_TIMEOUT * 2) && tcp_con_state == 1)	// If there is no response from the controller for HB_TIMEOUT seconds reset the connection
		{
			tcp_con_state = -1;
			if(Zodiac_Config.failstate == 0) clear_flows();		// Clear the flow if in secure mode
			tcp_close(tcp_pcb);
		}

		if (tcp_con_state < 1) tcp_wait++;	//Increment tcp wait counter

		if (tcp_con_state == -1 && tcp_wait > 3)	// Wait 3 seconds then try to connect again
		{
			tcp_con_state = 0;
			tcp_wait = 0;
		}
	}

}

/*
*	TCP callback function
*
*	@param *arg - additional arguments
*	@param tcp_pcb - TCP struct.
*	@param err - TCP error code.
*
*/
err_t TCPready(void *arg, struct tcp_pcb *tpcb, err_t err)
{
	tcp_con_state = true;
	tcp_recv(tpcb, of_receive);
	tcp_poll(tpcb, NULL, 4);
	tcp_err(tpcb, NULL);
	if(Zodiac_Config.failstate == 0) clear_flows();		// Clear the flow if in secure mode
	TRACE("Connected to controller");
	OF_hello();
	return ERR_OK;
}

/*
*	TCP connection error callback function
*
*	@param *arg - additional arguments
*	@param err - TCP error code.
*
*/
void tcp_error(void * arg, err_t err)
{
	if (err == ERR_TIMEOUT){
		tcp_pcb = NULL;
	}
	tcp_con_state = -1;
	return;
}

/*
*	OpenFlow FLOW Removed message function
*
*	@param flowid - flow number.
*	@param reason - the reason the flow was removed.
*
*/
void flowrem_notif(int flowid, uint8_t reason)
{
	struct ofp_flow_removed ofr;
	double diff;

	ofr.header.type = OFPT10_FLOW_REMOVED;
	ofr.header.version = OF_Version;
	ofr.header.length = htons(sizeof(struct ofp_flow_removed));
	ofr.header.xid = 0;
	ofr.cookie = flow_match[flowid].cookie;
	ofr.reason = reason;
	ofr.priority = flow_match[flowid].priority;
	diff = (totaltime/2) - flow_counters[flowid].duration;
	ofr.duration_sec = htonl(diff);
	ofr.packet_count = flow_counters[flowid].hitCount;
	ofr.byte_count = flow_counters[flowid].bytes;
	ofr.idle_timeout = flow_match[flowid].idle_timeout;
	ofr.match = flow_match[flowid].match;
	tcp_write(tcp_pcb, &ofr, sizeof(struct ofp_flow_removed), TCP_WRITE_FLAG_COPY);
	tcp_sent(tcp_pcb, NULL);
	tcp_output(tcp_pcb);
	return;
}

