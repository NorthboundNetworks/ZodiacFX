/**
 * @file
 * switch.h
 *
 * This file contains the timer functions
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

#ifndef SWITCH_H_
#define SWITCH_H_

#define SPI_Handler     SPI_Handler
#define SPI_IRQn        SPI_IRQn

void spi_init(void);
void switch_init(void);
void task_switch(struct netif *netif);
void switch_task(struct netif *netif);
void gmac_write(const void *p_buffer, uint16_t ul_size, uint8_t port);
uint64_t switch_read(uint8_t param1);
void switch_write(uint8_t param1, uint8_t param2);
void update_port_stats(void);
void update_port_status(void);
void disableOF(void);
void enableOF(void);
void stacking_init(bool master);
void stack_write(uint8_t data);

void sync_switch_port_counts(uint8_t);

// kwi //
uint32_t get_switch_config(uint32_t);
uint32_t get_switch_status(uint32_t);
uint32_t get_switch_ofppf13_curr(uint32_t);
uint32_t get_switch_ofppf13_advertised(uint32_t);
uint32_t get_switch_ofppf13_peer(uint32_t);

#endif /* SWITCH_H_ */