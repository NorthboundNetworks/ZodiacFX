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
#define SHARED_BUFFER_LEN 2048

void spi_init(void);
void switch_init(void);
void task_switch(struct netif *netif);
void gmac_write(uint8_t *p_buffer, uint16_t ul_size, uint8_t port);
int switch_read(uint8_t param1);
int switch_write(uint8_t param1, uint8_t param2);
void update_port_stats(void);
void update_port_status(void);
void disableOF(void);
void enableOF(void);

int readtxbytes(int port);
int readrxbytes(int port);
int readtxdrop(int port);
int readrxdrop(int port);
int readrxcrcerr(int port);
#endif /* SWITCH_H_ */
