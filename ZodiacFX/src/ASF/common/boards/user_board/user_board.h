/**
 * \file
 *
 * \brief User board definition template
 *
 */

 /* This file is intended to contain definitions and configuration details for
 * features and devices that are available on the board, e.g., frequency and
 * startup time for an external crystal, external memory devices, LED and USART
 * pins.
 */
/*
 * Support and FAQ: visit <a href="http://www.atmel.com/design-support/">Atmel Support</a>
 */

#ifndef USER_BOARD_H
#define USER_BOARD_H

#include <conf_board.h>

/** Board oscillator settings */
#define BOARD_FREQ_SLCK_XTAL            (32768U)
#define BOARD_FREQ_SLCK_BYPASS          (32768U)
#define BOARD_FREQ_MAINCK_XTAL          (12000000U)
#define BOARD_FREQ_MAINCK_BYPASS        (12000000U)

/** Master clock frequency */
#define BOARD_MCK                       CHIP_FREQ_CPU_MAX

/** board main clock xtal startup time */
#define BOARD_OSC_STARTUP_US            15625

/** Name of the board */
#define BOARD_NAME "ZODIAC"
/** Board definition */
#define zodiac
/** Family definition (already defined) */
#define sam4e
/** Core definition */
#define cortexm4

/*----------------------------------------------------------------------------*/
/* GMAC HW configurations */
#define BOARD_GMAC_PHY_ADDR 0

/*----------------------------------------------------------------------------*/

/** TWI0 pins definition */
#define TWI0_DATA_GPIO   PIO_PA3_IDX
#define TWI0_DATA_FLAGS  (IOPORT_MODE_MUX_A)
#define TWI0_CLK_GPIO    PIO_PA4_IDX
#define TWI0_CLK_FLAGS   (IOPORT_MODE_MUX_A)

/** USART0 pin RX */
#define PIN_USART0_RXD        {PIO_PB0C_RXD0, PIOB, ID_PIOB, PIO_PERIPH_C, PIO_DEFAULT}
#define PIN_USART0_RXD_IDX    (PIO_PB0_IDX)
#define PIN_USART0_RXD_FLAGS  (IOPORT_MODE_MUX_C)
/** USART0 pin TX */
#define PIN_USART0_TXD        {PIO_PB1C_TXD0, PIOB, ID_PIOB, PIO_PERIPH_C, PIO_DEFAULT}
#define PIN_USART0_TXD_IDX    (PIO_PB1_IDX)
#define PIN_USART0_TXD_FLAGS  (IOPORT_MODE_MUX_C)
/** USART0 pin CTS */
#define PIN_USART0_CTS        {PIO_PB2C_CTS0, PIOB, ID_PIOB, PIO_PERIPH_C, PIO_DEFAULT}
#define PIN_USART0_CTS_IDX    (PIO_PB2_IDX)
#define PIN_USART0_CTS_FLAGS  (IOPORT_MODE_MUX_C)
/** USART0 pin RTS */
#define PIN_USART0_RTS        {PIO_PB3C_RTS0, PIOB, ID_PIOB, PIO_PERIPH_C, PIO_DEFAULT}
#define PIN_USART0_RTS_IDX    (PIO_PB3_IDX)
#define PIN_USART0_RTS_FLAGS  (IOPORT_MODE_MUX_C)
/** USART0 pin SCK */
#define PIN_USART0_SCK        {PIO_PB13C_SCK0, PIOB, ID_PIOB, PIO_PERIPH_C, PIO_DEFAULT}
#define PIN_USART0_SCK_IDX    (PIO_PB13_IDX)
#define PIN_USART0_SCK_FLAGS  (IOPORT_MODE_MUX_C)

/** SPI MISO pin definition. */
#define SPI_MISO_GPIO         (PIO_PA12_IDX)
#define SPI_MISO_FLAGS        (IOPORT_MODE_MUX_A)
/** SPI MOSI pin definition. */
#define SPI_MOSI_GPIO         (PIO_PA13_IDX)
#define SPI_MOSI_FLAGS        (IOPORT_MODE_MUX_A)
/** SPI SPCK pin definition. */
#define SPI_SPCK_GPIO         (PIO_PA14_IDX)
#define SPI_SPCK_FLAGS        (IOPORT_MODE_MUX_A)
/** SPI chip select 0 pin definition. */
#define SPI_NPCS0_GPIO        (PIO_PA11_IDX)
#define SPI_NPCS0_FLAGS       (IOPORT_MODE_MUX_A)

/** USB D- pin (System function) */
#define PIN_USB_DM      {PIO_PB10}
/** USB D+ pin (System function) */
#define PIN_USB_DP      {PIO_PB11}
	
/** Master Select Jumper */
#define MASTER_SEL IOPORT_CREATE_PIN(PIOD, 28)
/** SPI Header IRQ Jumper */
#define SPI_IRQ1 IOPORT_CREATE_PIN(PIOD, 29)

/* KSZ8795CLX relate PIN definition */
#define PIN_KSZ8795CLX_RXC_IDX                 PIO_PD14_IDX
#define PIN_KSZ8795CLX_RXC_FLAGS             (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_TXC_IDX                 PIO_PD0_IDX
#define PIN_KSZ8795CLX_TXC_FLAGS             (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_TXEN_IDX                PIO_PD1_IDX
#define PIN_KSZ8795CLX_TXEN_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_TXD3_IDX                PIO_PD16_IDX
#define PIN_KSZ8795CLX_TXD3_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_TXD2_IDX                PIO_PD15_IDX
#define PIN_KSZ8795CLX_TXD2_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_TXD1_IDX                PIO_PD3_IDX
#define PIN_KSZ8795CLX_TXD1_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_TXD0_IDX                PIO_PD2_IDX
#define PIN_KSZ8795CLX_TXD0_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_TXER_IDX                PIO_PD17_IDX
#define PIN_KSZ8795CLX_TXER_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_RXD3_IDX                PIO_PD12_IDX
#define PIN_KSZ8795CLX_RXD3_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_RXD2_IDX                PIO_PD11_IDX
#define PIN_KSZ8795CLX_RXD2_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_RXD1_IDX                PIO_PD6_IDX
#define PIN_KSZ8795CLX_RXD1_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_RXD0_IDX                PIO_PD5_IDX
#define PIN_KSZ8795CLX_RXD0_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_RXER_IDX                PIO_PD7_IDX
#define PIN_KSZ8795CLX_RXER_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_RXDV_IDX                PIO_PD4_IDX
#define PIN_KSZ8795CLX_RXDV_FLAGS            (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_CRS_IDX                 PIO_PD10_IDX
#define PIN_KSZ8795CLX_CRS_FLAGS             (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_COL_IDX                 PIO_PD13_IDX
#define PIN_KSZ8795CLX_COL_FLAGS             (IOPORT_MODE_MUX_A)
#define PIN_KSZ8795CLX_INTRP_IDX               PIO_PD28_IDX


/*----------------------------------------------------------------------------*/
/**
 * \page zodiac_usb "ZODIAC - USB device"
 *
 * \section Definitions
 * - \ref BOARD_USB_BMATTRIBUTES
 * - \ref CHIP_USB_UDP
 * - \ref CHIP_USB_PULLUP_INTERNAL
 * - \ref CHIP_USB_NUMENDPOINTS
 * - \ref CHIP_USB_ENDPOINTS_MAXPACKETSIZE
 * - \ref CHIP_USB_ENDPOINTS_BANKS
 */

/**
 * USB attributes configuration descriptor (bus or self powered,
 * remote wakeup)
 */
#define BOARD_USB_BMATTRIBUTES  USBConfigurationDescriptor_SELFPOWERED_RWAKEUP

/** Indicates chip has an UDP Full Speed. */
#define CHIP_USB_UDP

/** Indicates chip has an internal pull-up. */
#define CHIP_USB_PULLUP_INTERNAL

/** Number of USB endpoints */
#define CHIP_USB_NUMENDPOINTS 8

/** Endpoints max packet size */
#define CHIP_USB_ENDPOINTS_MAXPACKETSIZE(i) \
   ((i == 0) ? 64 : \
   ((i == 1) ? 64 : \
   ((i == 2) ? 64 : \
   ((i == 3) ? 64 : \
   ((i == 4) ? 512 : \
   ((i == 5) ? 512 : \
   ((i == 6) ? 64 : \
   ((i == 7) ? 64 : 0 ))))))))

/** Endpoints Number of Bank */
#define CHIP_USB_ENDPOINTS_BANKS(i) \
   ((i == 0) ? 1 : \
   ((i == 1) ? 2 : \
   ((i == 2) ? 2 : \
   ((i == 3) ? 1 : \
   ((i == 4) ? 2 : \
   ((i == 5) ? 2 : \
   ((i == 6) ? 2 : \
   ((i == 7) ? 2 : 0 ))))))))
   
/*----------------------------------------------------------------------------*/   

#endif // USER_BOARD_H
