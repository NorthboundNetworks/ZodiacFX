/**
 * @file
 * config_zodiac.h
 *
 * This file contains the configuration for the Zodiac FX
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

#ifndef CONFIG_ZODIAC_H_
#define CONFIG_ZODIAC_H_


#define VERSION "0.86"		// Firmware version number

#define TOTAL_PORTS 4		// Total number of physical ports on the Zodiac FX

#define MAX_OFP_VERSION   0x04

#define MAX_FLOWS_10	128		// Maximum number of flows for OpenFlow 1.0
#define MAX_FLOWS_13	480		// Maximum number of flows for OpenFlow 1.3

#define MAX_VLANS	4	// Maximum number of VLANS, default is 1 per port (4)

#define MAX_TABLES	10	// Maximum number of tables for OpenFlow 1.3 and higher

#define MAX_GROUPS 4	// Maximum number of groups for OpenFlow 1.3 and higher
#define MAX_BUCKETS 4	// Maximum number of group action buckets for OpenFlow 1.3 and higher

#define HB_INTERVAL	2	// Number of seconds between heartbeats
#define HB_TIMEOUT	6	// Number of seconds to wait when there is no response from the controller

#define MAX_OF_STATS	15		// Maximum number of flows to send to controller

#define MAX_METER_13	8		// Maximum number of meter entries in meter table
#define MAX_METER_BANDS_13	3	// Maximum number of meter bands per meter
#define POLICING_SAMPLES	20	// Sample for rate limiter
#define	POLICING_SLICE		2	// time (ms) slice for each sample

#endif /* CONFIG_ZODIAC_H_ */
