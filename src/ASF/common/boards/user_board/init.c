/**
 * \file
 *
 * \brief User board initialization template
 *
 */
/*
 * Support and FAQ: visit <a href="http://www.atmel.com/design-support/">Atmel Support</a>
 */

#include "compiler.h"
#include "board.h"
#include "conf_board.h"
#include "ioport.h"

/**
 * \brief Set peripheral mode for IOPORT pins.
 * It will configure port mode and disable pin mode (but enable peripheral).
 * \param port IOPORT port to configure
 * \param masks IOPORT pin masks to configure
 * \param mode Mode masks to configure for the specified pin (\ref ioport_modes)
 */
#define ioport_set_port_peripheral_mode(port, masks, mode) \
	do {\
		ioport_set_port_mode(port, masks, mode);\
		ioport_disable_port(port, masks);\
	} while (0)

/**
 * \brief Set peripheral mode for one single IOPORT pin.
 * It will configure port mode and disable pin mode (but enable peripheral).
 * \param pin IOPORT pin to configure
 * \param mode Mode masks to configure for the specified pin (\ref ioport_modes)
 */
#define ioport_set_pin_peripheral_mode(pin, mode) \
	do {\
		ioport_set_pin_mode(pin, mode);\
		ioport_disable_pin(pin);\
	} while (0)

/**
 * \brief Set input mode for one single IOPORT pin.
 * It will configure port mode and disable pin mode (but enable peripheral).
 * \param pin IOPORT pin to configure
 * \param mode Mode masks to configure for the specified pin (\ref ioport_modes)
 * \param sense Sense for interrupt detection (\ref ioport_sense)
 */
#define ioport_set_pin_input_mode(pin, mode, sense) \
	do {\
		ioport_set_pin_dir(pin, IOPORT_DIR_INPUT);\
		ioport_set_pin_mode(pin, mode);\
		ioport_set_pin_sense_mode(pin, sense);\
	} while (0)

void board_init(void)
{
	
#ifndef CONF_BOARD_KEEP_WATCHDOG_AT_INIT
/* Disable the watchdog */
WDT->WDT_MR = WDT_MR_WDDIS;
#endif
	
#ifdef CONF_BOARD_TWI0
ioport_set_pin_peripheral_mode(TWI0_DATA_GPIO, TWI0_DATA_FLAGS);
ioport_set_pin_peripheral_mode(TWI0_CLK_GPIO, TWI0_CLK_FLAGS);
#endif

#ifdef CONF_BOARD_USART_RXD
/* Configure USART RXD pin */
ioport_set_pin_peripheral_mode(PIN_USART0_RXD_IDX, PIN_USART0_RXD_FLAGS);
#endif

#ifdef CONF_BOARD_USART_TXD
/* Configure USART TXD pin */
ioport_set_pin_peripheral_mode(PIN_USART0_TXD_IDX, PIN_USART0_TXD_FLAGS);
#endif

#ifdef CONF_BOARD_USART_CTS
/* Configure USART CTS pin */
ioport_set_pin_peripheral_mode(PIN_USART0_CTS_IDX, PIN_USART0_CTS_FLAGS);
#endif

#ifdef CONF_BOARD_USART_RTS
/* Configure USART RTS pin */
ioport_set_pin_peripheral_mode(PIN_USART0_RTS_IDX, PIN_USART0_RTS_FLAGS);
#endif

#ifdef CONF_BOARD_USART_SCK
/* Configure USART synchronous communication SCK pin */
ioport_set_pin_peripheral_mode(PIN_USART0_SCK_IDX, PIN_USART0_SCK_FLAGS);
#endif

#ifdef CONF_BOARD_SPI
ioport_set_pin_peripheral_mode(SPI_MISO_GPIO, SPI_MISO_FLAGS);
ioport_set_pin_peripheral_mode(SPI_MOSI_GPIO, SPI_MOSI_FLAGS);
ioport_set_pin_peripheral_mode(SPI_SPCK_GPIO, SPI_SPCK_FLAGS);
ioport_set_pin_peripheral_mode(SPI_NPCS0_GPIO, SPI_NPCS0_FLAGS);
#endif

#ifdef CONF_BOARD_KSZ8795CLX
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_RXC_IDX, PIN_KSZ8795CLX_RXC_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_TXC_IDX, PIN_KSZ8795CLX_TXC_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_TXEN_IDX,PIN_KSZ8795CLX_TXEN_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_TXD3_IDX,PIN_KSZ8795CLX_TXD3_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_TXD2_IDX,PIN_KSZ8795CLX_TXD2_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_TXD1_IDX,PIN_KSZ8795CLX_TXD1_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_TXD0_IDX,PIN_KSZ8795CLX_TXD0_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_TXER_IDX,PIN_KSZ8795CLX_TXER_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_RXD3_IDX,PIN_KSZ8795CLX_RXD3_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_RXD2_IDX,PIN_KSZ8795CLX_RXD2_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_RXD1_IDX,PIN_KSZ8795CLX_RXD1_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_RXD0_IDX,PIN_KSZ8795CLX_RXD0_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_RXER_IDX,PIN_KSZ8795CLX_RXER_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_RXDV_IDX,PIN_KSZ8795CLX_RXDV_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_CRS_IDX,PIN_KSZ8795CLX_CRS_FLAGS);
ioport_set_pin_peripheral_mode(PIN_KSZ8795CLX_COL_IDX,PIN_KSZ8795CLX_COL_FLAGS);
ioport_set_pin_dir(PIN_KSZ8795CLX_INTRP_IDX, IOPORT_DIR_INPUT);
#endif

}