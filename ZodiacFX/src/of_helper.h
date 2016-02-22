/**
 * @file
 * of_helper.h
 *
 * This file contains the function declarations and structures for the OpenFlow helper functions
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


#ifndef OF_HELPER_H_
#define OF_HELPER_H_

#include "openflow.h"
#include <lwip/pbuf.h>

void set_ip_checksum(void *p_uc_data, uint16_t packet_size, uint16_t iphdr_offset);

// --- kwi ---
bool oxm_strict_equals(const void*, int, const void*, int);

#endif /* OF_HELPER_H_ */