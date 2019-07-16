/**
 * vi: ts=4:sw=4
 *
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
extern uint8_t port_status[TOTAL_PORTS];
extern struct ofp10_port_stats phys10_port_stats[TOTAL_PORTS];
extern struct ofp13_port_stats phys13_port_stats[TOTAL_PORTS];

// Local Variables
struct ofp_switch_config Switch_config;
struct ofp_flow_mod *flow_match10[MAX_FLOWS_10];
struct ofp13_flow_mod *flow_match13[MAX_FLOWS_13];
struct group_entry13 group_entry13[MAX_GROUPS];
struct action_bucket action_bucket[MAX_BUCKETS];
uint8_t *ofp13_oxm_match[MAX_FLOWS_13];
uint8_t *ofp13_oxm_inst[MAX_FLOWS_13];
uint16_t ofp13_oxm_inst_size[MAX_FLOWS_13];
struct flows_counter flow_counters[MAX_FLOWS_13];
struct flow_tbl_actions *flow_actions10[MAX_FLOWS_10];
struct table_counter table_counters[MAX_TABLES];
int iLastFlow = 0;
int iLastMeter = 0;
struct meter_entry13 *meter_entry[MAX_METER_13];
struct meter_band_stats_array band_stats_array[MAX_METER_13];
uint8_t shared_buffer[SHARED_BUFFER_LEN];
char sysbuf[64];
struct ip_addr serverIP;
int OF_Version = 0x00;
struct tcp_pcb *tcp_pcb;
struct tcp_pcb *tcp_pcb_check;
int fast_of_timer = 0;
int tcp_con_state = -1;
int tcp_wait = 0;
int totaltime = 0;
int heartbeat = 0;
uint32_t reply_more_xid = 0;
bool reply_more_flag = false;
bool rcv_freq;

// Buffer for multi-segment messages
#define PACKET_BUFFER_SIZE		(2*TCP_MSS+64)	// TODO: Ideally would be (2*1536)
static uint8_t packet_buffer[PACKET_BUFFER_SIZE];
static unsigned int packet_buffer_off = 0;
static unsigned int packet_buffer_len = 0;

// Internal Functions
void OF_hello(void);
void echo_request(void);
void echo_reply(struct ofp_header *ofph, int len);
err_t TCPready(void *arg, struct tcp_pcb *tpcb, err_t err);
void tcp_error(void * arg, err_t err);
static err_t of_receive(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t of_sent(void *arg, struct tcp_pcb *tpcb, uint16_t len);

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
*	Main OpenFlow table lookup Function
*
*	@param p_uc_data - pointer to the packet buffer.
*	@param ul_size - Size of the packet.
*	@param port	- In Port.
*
*/
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
	heartbeat = 0;	// Reset heartbeat counter

	if (err == ERR_OK && p != NULL)
	{
		int plen = p->tot_len;	//size of the payload
		if (packet_buffer_len + plen > PACKET_BUFFER_SIZE) {
			TRACE("openflow.c: packet buffer exceeded, aborting!!!");
			return ERR_ABRT;
		}
		memcpy(&packet_buffer[packet_buffer_len], p->payload, plen);	// append to our own buffer
		packet_buffer_len += plen;
		TRACE("openflow.c: OpenFlow data received (%d bytes)", plen);

		// Accept the TCP data and release the packet
		tcp_recved(tpcb, plen);
		pbuf_free(p);

		while (packet_buffer_off < packet_buffer_len)
		{
			struct ofp_header *ofph = &packet_buffer[packet_buffer_off];
			if (ofph->length == 0 || ofph->version == 0){
				TRACE("openflow.c: Invalid OpenFlow packet, aborting!");
				return ERR_ABRT;
			}
			if (ofph->version > 6 || ofph->type > 30)
			{
				TRACE("openflow.c: Invalid OpenFlow packet values, aborting!");
				return ERR_ABRT;
			}

			int ofp_len = htons(ofph->length);
			if ((packet_buffer_off + ofp_len) > packet_buffer_len)
			{
				// TRACE("openflow.c: Partial OpenFlow message - waiting for more data...");
				break;
			}
			packet_buffer_off += ofp_len;
			TRACE("openflow.c: Processing %d byte OpenFlow message %u", ofp_len, htonl(ofph->xid));

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
					echo_reply(ofph, ofp_len);
				break;

				default:
					if (OF_Version == 0x01) of10_message(ofph, ofp_len);
					if (OF_Version == 0x04) of13_message(ofph, ofp_len);
			};
		}

		if (packet_buffer_off == packet_buffer_len) {
			packet_buffer_off = 0;
			packet_buffer_len = 0;
		} else {
			unsigned int rem = packet_buffer_len - packet_buffer_off;
			memcpy(packet_buffer, &packet_buffer[packet_buffer_off], rem);
			packet_buffer_off = 0;
			packet_buffer_len = rem;
			TRACE("openflow.c: Partial OpenFlow message - keeping %d bytes", rem);
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
*	OpenFlow Sent callback function
*
*	@param *arg - pointer the additional TCP args
*	@param *tcp_pcb - pointer the TCP session structure.
*
*/
static err_t of_sent(void *arg, struct tcp_pcb *tpcb, uint16_t len)
{
	TRACE("openflow.c: [of_sent] %d bytes acknowledged ", len);
	if(reply_more_flag == true)
	{
		multi_flow_more_reply13();
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
	TRACE("openflow.c: Sending HELLO, version 0x%d", ofph.version);
	sendtcp(&ofph, sizeof(ofph), 1);
	return;
}

/*
*	OpenFlow ECHO Reply message function
*
*	@param xid - transaction ID
*
*/
void echo_reply(struct ofp_header *ofph, int len)
{
	// Change the message type to Echo Reply and return any data that was sent
	ofph->type   = OFPT10_ECHO_REPLY;
	TRACE("openflow.c: Sent ECHO reply");
	sendtcp(ofph, len, 1);
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
	TRACE("openflow.c: Sent ECHO request");
	sendtcp(&echo, sizeof(echo), 1);
	return;
}

/*
*	TCP send packet function
*
*	@param *buffer - pointer to the buffer containing the data to send.
*	@param len - size of the packet to send
*
*/
void sendtcp(const void *buffer, uint16_t len, uint8_t push)
{
	err_t err;
	uint16_t buf_size;
	
	if( tcp_pcb != tcp_pcb_check)
	{
		tcp_con_state = -1;
		tcp_pcb = NULL;
		return;
	}
	
	buf_size = tcp_sndbuf(tcp_pcb);
	if (push == 0)
	{
		TRACE("openflow.c: Sending %d bytes to TCP stack, %d available in buffer", len, buf_size);
		err = tcp_write(tcp_pcb, buffer, len, TCP_WRITE_FLAG_COPY + TCP_WRITE_FLAG_MORE);
	
	} else {
		TRACE("openflow.c: Sending %d bytes immediately, %d available in buffer", len, buf_size);
		err = tcp_write(tcp_pcb, buffer, len, TCP_WRITE_FLAG_COPY);
		tcp_output(tcp_pcb);
	}

	return;
}

/*
*	Main OpenFlow processing loop
*
*/
void task_openflow(void)
{

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
				TRACE("openflow.c: Closing connection due to failed handshake!");
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
			TRACE("openflow.c: Closing connection due to no heartbeat!");
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
	packet_buffer_off = 0;
	packet_buffer_len = 0;
	tcp_con_state = true;
	tcp_recv(tpcb, of_receive);
	tcp_poll(tpcb, NULL, 4);
	tcp_err(tpcb, NULL);
	tcp_sent(tpcb, of_sent);
	if(Zodiac_Config.failstate == 0) clear_flows();		// Clear the flow if in secure mode
	TRACE("openflow.c: Connected to controller");
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



