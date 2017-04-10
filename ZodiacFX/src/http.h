/**
 * @file
 * http.h
 *
 * This file contains the http functions
 *
 */

/*
 * This file is part of the Zodiac FX firmware.
 * Copyright (c) 2016 Google Inc.
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
 * Authors: Paul Zanna <paul@northboundnetworks.com>
 *		  & Kristopher Chen <Kristopher@northboundnetworks.com>
 *
 */

#ifndef HTTP_H_
#define HTTP_H_

#define FLOW_DISPLAY_LIMIT	4	// Displayable flows per page
#define	METER_DISPLAY_LIMIT	3	// Displayable meters per page
#define BOUNDARY_MAX_LEN	70
#define PAGEBUFF_SIZE		IFLASH_PAGE_SIZE + BOUNDARY_MAX_LEN
#define UPLOAD_TIMEOUT		25000	// (ms) timeout window between each firmware update packet
#define MAX_CONN			4		// Maximum http connection status structs

struct http_conns
{
	int bytes_waiting;
	struct tcp_pcb *attached_pcb;
	uint32_t timeout;
};

void http_init(void);

#endif /* HTTP_H_ */