/*
 * stacking.h
 *
 * Created: 1/04/2017 5:30:12 PM
 *  Author: paul
 */ 


#ifndef STACKING_H_
#define STACKING_H_

#define SPI_Handler     SPI_Handler
#define SPI_IRQn        SPI_IRQn

void stacking_init(bool master);
void MasterStackSend(uint8_t *p_uc_data, uint16_t ul_size);
void MasterStackRcv(void);


#endif /* STACKING_H_ */