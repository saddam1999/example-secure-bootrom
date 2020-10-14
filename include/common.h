/******************************************************************************
 *
 * Secure BootRom (SBR)
 *
 ******************************************************************************
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 ******************************************************************************/

/**
 * @file common.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef INCLUDE_COMMON_H_
#define INCLUDE_COMMON_H_

/** Global includes */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <metal/memory.h>
#include <metal/cpu.h>
#include <metal/uart.h>
#include <metal/led.h>
/** Other includes */
#include <api/scl_api.h>
#include <api/hardware/scl_hca.h>
#include <scl/scl_sha.h>
//#include <api/software/bignumbers/soft_bignumbers.h>
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#ifndef TRUE
#define	TRUE									1
#endif /* TRUE */

#ifndef FALSE
#define	FALSE									0
#endif /* FALSE */

#ifndef NULL
#define	NULL									((void*)0UL)
#endif /* NULL */

#ifndef _WITH_FREEDOM_METAL_
#define	C_OTP_BASE_ADDRESS						0xe00000000ULL
#define	C_IRAM_BASE_ADDRESS						0x80000000ULL
#define	C_QSPI_BASE_ADDRESS						0xd00000000ULL
#else
#define	C_OTP_BASE_ADDRESS						__otp_start_address
#define	C_IRAM_BASE_ADDRESS						__ram_start_address
//#define	C_QSPI_BASE_ADDRESS						__qflash_start_address
#define	C_QSPI_BASE_ADDRESS						0xd00000000ULL
#endif /* _WITH_NO_FREEDOM_METAL */

/** Version *******************************************************************/
#ifndef MAJOR_VERSION
#define	SBR_VERSION_MAJOR						0x00
#else
#define	SBR_VERSION_MAJOR						MAJOR_VERSION
#endif /* MAJOR_VERSION */
#define	C_SBR_VERSION_MAJOR_OFST				24
#define	C_SBR_VERSION_MAJOR_MASK_NOOFST			0xff
#define	C_SBR_VERSION_MAJOR_MASK				( C_SBR_VERSION_MAJOR_MASK_NOOFST << C_SBR_VERSION_MAJOR_OFST )

#ifndef MINOR_VERSION
#define	SBR_VERSION_MINOR						0x00
#else
#define	SBR_VERSION_MINOR						MINOR_VERSION
#endif /* MINOR_VERSION */
#define	C_SBR_VERSION_MINOR_OFST				16
#define	C_SBR_VERSION_MINOR_MASK_NOOFST			0xff
#define	C_SBR_VERSION_MINOR_MASK				( C_SBR_VERSION_MINOR_MASK_NOOFST << C_SBR_VERSION_MINOR_OFST )


#ifndef EDIT_VERSION
#define	SBR_VERSION_EDIT						0x0002
#else
#define	SBR_VERSION_EDIT						EDIT_VERSION
#endif /* EDIT_VERSION */
#define	C_SBR_VERSION_EDIT_OFST					0
#define	C_SBR_VERSION_EDIT_MASK_NOOFST			0xffff
#define	C_SBR_VERSION_EDIT_MASK					( C_SBR_VERSION_EDIT_MASK_NOOFST << C_SBR_VERSION_EDIT_OFST )

#ifndef REF_MAJOR_VERSION
#define	SBR_REF_VERSION_MAJOR					0x00
#else
#define	SBR_REF_VERSION_MAJOR					REF_MAJOR_VERSION
#endif /* REF_MAJOR_VERSION */
#define	C_SBR_REF_VERSION_MAJOR_OFST			24
#define	C_SBR_REF_VERSION_MAJOR_MASK_NOOFST		0xff
#define	C_SBR_REF_VERSION_MAJOR_MASK			( C_SBR_REF_VERSION_MAJOR_MASK_NOOFST << C_SBR_REF_VERSION_MAJOR_OFST )

#ifndef REF_MINOR_VERSION
#define	SBR_REF_VERSION_MINOR					0x00
#else
#define	SBR_REF_VERSION_MINOR					REF_MINOR_VERSION
#endif /* REF_MINOR_VERSION */
#define	C_SBR_REF_VERSION_MINOR_OFST			16
#define	C_SBR_REF_VERSION_MINOR_MASK_NOOFST		0xff
#define	C_SBR_REF_VERSION_MINOR_MASK			( C_SBR_REF_VERSION_MINOR_MASK_NOOFST << C_SBR_REF_VERSION_MINOR_OFST )


#ifndef REF_EDIT_VERSION
#define	SBR_REF_VERSION_EDIT					0x0001
#else
#define	SBR_REF_VERSION_EDIT					REF_EDIT_VERSION
#endif /* REF_EDIT_VERSION */
#define	C_SBR_REF_VERSION_EDIT_OFST				0
#define	C_SBR_REF_VERSION_EDIT_MASK_NOOFST		0xffff
#define	C_SBR_REF_VERSION_EDIT_MASK				( C_SBR_REF_VERSION_EDIT_MASK_NOOFST << C_SBR_REF_VERSION_EDIT_OFST )

/******************************************************************************/
#define	C_GENERIC_KILO							1024
#define	C_GENERIC_MEGA							( C_GENERIC_KILO * C_GENERIC_KILO )

#define	C_AES128_SIZE							0x10
#define	C_AES256_SIZE							( 2 * C_AES128_SIZE )

#define	C_TRNG_SIZE								0x10
#define	C_TRNG_SIZE_32BITS						( C_TRNG_SIZE / sizeof(uint32_t) )

#define	C_EDCSA256_SIZE							0x20
#define	C_EDCSA384_SIZE							0x30
#define	C_EDCSA384_SIZE_BITS					( 8 * C_EDCSA384_SIZE )

#define	C_RSA2048_SIZE							0x100
#define	C_RSA4096_SIZE							( 2 * C_RSA2048_SIZE )

#define	C_CRC32_SIZE							0x20

#define	C_PATTERN_VIRGIN_8BITS					0xffU
#define	C_PATTERN_VIRGIN_16BITS					0xffffU
#define	C_PATTERN_VIRGIN_32BITS					0xffffffffUL
#define	C_PATTERN_VIRGIN_64BITS					0xffffffffffffffffULL
#if (__riscv_xlen == 32)
/** 32bits */
#define	C_PATTERN_VIRGIN_MAXBITS				0xffffffffULL
#elif (__riscv_xlen == 64)
/** 64bits */
#define	C_PATTERN_VIRGIN_MAXBITS				0xffffffffffffffffULL
#else
/** 128bits */
#define	C_PATTERN_VIRGIN_MAXBITS				0xffffffffffffffffffffffffffffffffULLL
#endif /* __riscv_xlen */

#define	C_MISA_WIRI_OFST						26
#define	C_MISA_WIRI_MASK_NOOFST					0x3
#define	C_MISA_WIRI_MASK						( C_MISA_WIRI_MASK_NOOFST << C_MISA_WIRI_OFST )

#define	C_MISA_WIRI_ISA_WITDH_32BITS			0x1
#define	C_MISA_WIRI_ISA_WIDTH_64BITS			0x2
#define	C_MISA_WIRI_ISA_WIDTH_128BITS			0x3

#define	C_MISA_EXTENSION_BIT_ATOMIC_OFST		0
#define	C_MISA_EXTENSION_BIT_COMPRESSED_OFST	2
#define	C_MISA_EXTENSION_BIT_DP_FLOAT_OFST		3
#define	C_MISA_EXTENSION_BIT_RV32E_OFST			4
#define	C_MISA_EXTENSION_BIT_SP_FLOAT_OFST		5
#define	C_MISA_EXTENSION_BIT_ADD_EXT_OFST		6
#define	C_MISA_EXTENSION_BIT_HYPER_MODE_OFST	7
#define	C_MISA_EXTENSION_BIT_RVxxI_OFST			8
#define	C_MISA_EXTENSION_BIT_INT_MULDIV_OFST	12
#define	C_MISA_EXTENSION_BIT_USER_IRQ_OFST		13
#define	C_MISA_EXTENSION_BIT_QP_FLOAT_OFST		16
#define	C_MISA_EXTENSION_BIT_SUPER_MODE_OFST	18
#define	C_MISA_EXTENSION_BIT_USER_MODE_OFST		20
#define	C_MISA_EXTENSION_BIT_NO_STD_EXT_OFST	23

/******************************************************************************/
#define	C_SIGNATURE_MAX_SIZE					( 2 * C_EDCSA384_SIZE )
#define	C_SIGNATURE_MAX_SIZE_INT				( C_SIGNATURE_MAX_SIZE / sizeof(uint32_t) )

#define	C_ADDRESS_SIZE_MAX						16

#define	C_MAX_CHECK_LOOP_NB						2

#define	C_UID_SIZE_IN_BYTES						16

#define	C_CRYPTO_LIB_BUFFER_SIZE				( 8 * C_GENERIC_KILO )
#define	C_CRYPTO_LIB_BUFFER_SIZE_INT			( C_CRYPTO_LIB_BUFFER_SIZE / sizeof(uint32_t) )

#ifdef _WITH_GPIO_CHARAC_
/******************************************************************************/
#define	C_GPIO0_OFFSET							8
#define	C_GPIO0_NB								8


#define	C_GPIO0_SHA								( C_GPIO0_OFFSET + 5 )
#define	C_GPIO0_SHA_ECDSA						( C_GPIO0_OFFSET + 6 )
#define	C_GPIO0_DIRECT_ECDSA					( C_GPIO0_OFFSET + 7 )

#define	C_GPIO0_HEADER_CHECK					( C_GPIO0_OFFSET + 12 )
#define	C_GPIO0_JUMP							( C_GPIO0_OFFSET + 13 )
#define	C_GPIO0_SBR_END							( C_GPIO0_OFFSET + 14 )


#endif /* _WITH_GPIO_CHARAC_ */

/** Enumerations **************************************************************/

/** Types definition **********************************************************/
#if (__riscv_xlen == 64)
typedef uint64_t							uint_pltfrm;
typedef int64_t								int_pltfrm;
#elif (__riscv_xlen == 32)
typedef uint32_t							uint_pltfrm;
typedef int32_t								int_pltfrm;
#else
#error [__riscv_xlen] A value for bus width must be defined
#endif /*  */

/** Structures ****************************************************************/
#ifdef _FPGA_SPECIFIC_
typedef struct
{
	int R : 1;
	int W : 1;
	int X : 1;
	int C : 1;
	int A : 1;

} _metal_memory_attributes;
#endif /* _FPGA_SPECIFIC_ */

#ifndef _WITH_SCR_REGISTERS_
#define	C_REG_SCR_BASE_ADDRESS					0x4f0010000ULL
#endif /* _WITH_SCR_REGISTERS_ */

/** UART defines **************************************************************/
/** TXDATA register */
#define	C_UART_TXDATA_DATA_OFST					0
#define	C_UART_TXDATA_DATA_MASK_NOOFST			0xff
#define	C_UART_TXDATA_DATA_MASK					( C_UART_TXDATA_DATA_MASK_NOOFST << C_UART_TXDATA_DATA_OFST )

#define	C_UART_TXDATA_FULL_OFST					31
#define	C_UART_TXDATA_FULL_MASK_NOOFST			0x1
#define	C_UART_TXDATA_FULL_MASK					( C_UART_TXDATA_FULL_MASK_NOOFST << C_UART_TXDATA_FULL_OFST )

/** RXDATA register */
#define	C_UART_RXDATA_DATA_OFST					0
#define	C_UART_RXDATA_DATA_MASK_NOOFST			0xff
#define	C_UART_RXDATA_DATA_MASK					( C_UART_RXDATA_DATA_MASK_NOOFST << C_UART_RXDATA_DATA_OFST )

#define	C_UART_RXDATA_EMPTY_OFST				31
#define	C_UART_RXDATA_EMPTY_MASK_NOOFST			0x1
#define	C_UART_RXDATA_EMPTY_MASK				( C_UART_RXDATA_EMPTY_MASK_NOOFST << C_UART_RXDATA_EMPTY_OFST )

/** Transmit Control Register */
#define	C_UART_TXCTRL_TXEN_OFST					0
#define	C_UART_TXCTRL_TXEN_MASK_NOOFST			0x1
#define	C_UART_TXCTRL_TXEN_MASK					( C_UART_TXCTRL_TXEN_MASK_NOOFST << C_UART_TXCTRL_TXEN_OFST )

#define	C_UART_TXCTRL_NSTOP_OFST				1
#define	C_UART_TXCTRL_NSTOP_MASK_NOOFST			0x1
#define	C_UART_TXCTRL_NSTOP_MASK				( C_UART_TXCTRL_NSTOP_MASK_NOOFST << C_UART_TXCTRL_NSTOP_OFST )

#define	C_UART_TXCTRL_TXCNT_OFST				16
#define	C_UART_TXCTRL_TXCNT_MASK_NOOFST			0x7
#define	C_UART_TXCTRL_TXCNT_MASK				( C_UART_TXCTRL_TXCNT_MASK_NOOFST << C_UART_TXCTRL_TXCNT_OFST )

/** Receive Control Register */
#define	C_UART_RXCTRL_RXEN_OFST					0
#define	C_UART_RXCTRL_RXEN_MASK_NOOFST			0x1
#define	C_UART_RXCTRL_RXEN_MASK					( C_UART_RXCTRL_RXEN_MASK_NOOFST << C_UART_RXCTRL_RXEN_OFST )

#define	C_UART_RXCTRL_RXCNT_OFST				16
#define	C_UART_RXCTRL_RXCNT_MASK_NOOFST			0x7
#define	C_UART_RXCTRL_RXCNT_MASK				( C_UART_RXCTRL_RXCNT_MASK_NOOFST << C_UART_RXCTRL_RXCNT_OFST )

/** Interrupt Enable register */
#define	C_UART_IE_TXWM_OFST						0
#define	C_UART_IE_TXWM_MASK_NOOFST				0x1
#define	C_UART_IE_TXWM_MASK						( C_UART_IE_TXWM_MASK_NOOFST << C_UART_IE_TXWM_OFST )

#define	C_UART_IE_RXWM_OFST						1
#define	C_UART_IE_RXWM_MASK_NOOFST				0x1
#define	C_UART_IE_RXWM_MASK						( C_UART_IE_RXWM_MASK_NOOFST << C_UART_IE_RXWM_OFST )

/** Interrupt Pending register */
#define	C_UART_IP_TXWM_OFST						0
#define	C_UART_IP_TXWM_MASK_NOOFST				0x1
#define	C_UART_IP_TXWM_MASK						( C_UART_IP_TXWM_MASK_NOOFST << C_UART_IP_TXWM_OFST )

#define	C_UART_IP_RXWM_OFST						1
#define	C_UART_IP_RXWM_MASK_NOOFST				0x1
#define	C_UART_IP_RXWM_MASK						( C_UART_IP_RXWM_MASK_NOOFST << C_UART_IP_RXWM_OFST )

/** Baud rate Divisor register */
#define	C_UART_DIV_DIV_OFST						0
#define	C_UART_DIV_DIV_MASK_NOOFST				0xffff
#define	C_UART_DIV_DIV_MASK						( C_UART_DIV_DIV_MASK_NOOFST << C_UART_DIV_DIV_OFST )

#define	C_UART_DATA_MAX_THRESHOLD_RX			( C_UART_RXCTRL_RXCNT_MASK_NOOFST + 1 )
#define	C_UART_DATA_MAX_THRESHOLD_TX			( C_UART_TXCTRL_TXCNT_MASK_NOOFST + 1 )

typedef struct
{
	/** Offset 0x00000000 - TX data register */
	uint32_t									tx;
	/** Offset 0x00000004 - RX data register */
	uint32_t									rx;
	/** Offset 0x00000008 - TX control register */
	uint32_t									tx_ctrl;
	/** Offset 0x0000000c - RX control register */
	uint32_t									rx_ctrl;
	/** Offset 0x00000010 - Interrupt enable register */
	uint32_t									ie;
	/** Offset 0x00000014 - Interrupt pending register */
	uint32_t									ip;
	/** Offset 0x00000018 - Baud rate divisor register */
	uint32_t									div;

} t_reg_uart;


/** Security Descriptor */
typedef struct __attribute__((packed))
{
	/** Signing Key Identifier */
	uint8_t										skid;
	/** Algorithm Identifier */
	uint8_t										algo_id;
	/** Key size */
	uint16_t									size;

} t_security_decriptor;

typedef struct __attribute__((packed))
{
	/** Magic trampoline */
	uint64_t									magic_trampoline1;
	uint64_t									magic_trampoine2;
	/** Magic words */
	uint32_t									magic_word1;
	uint32_t									magic_word2;
	/** Secure Boot ROM reference version */
	uint32_t									rom_ref_version;
	/** Firmware Version */
	uint32_t									firmware_version;
	/** Application Type */
	uint16_t									appli_type;
	/** Address Size */
	uint16_t									address_size;
	/** Secure Application image Size */
	uint32_t									secure_appli_image_size;
	/** Firmware Start Offset */
	uint32_t									fimware_start_offset;
	/** Copy Address */
	uint32_t									copy_address[( C_ADDRESS_SIZE_MAX / sizeof(uint32_t) )];
	/** Execution Address */
	uint32_t									execution_address[( C_ADDRESS_SIZE_MAX / sizeof(uint32_t) )];
	/** Signature information - 4 Bytes */
	/** Algorithm */
	uint8_t										algo;
	/** Number of signatures */
	uint8_t										nb_signatures;
	/** Signing key #1 identifier */
	uint8_t										sign_keyid_1;
	/** Signing key #2 identifier */
	uint8_t										sign_keyid_2;
	/** Key size in bits */
	uint16_t									signature_size_bits;
	/** Signature */
	uint8_t										signature[C_SIGNATURE_MAX_SIZE];

} t_secure_header;

typedef struct
{
	/** Core MISA where Secure Boot ROM runs*/
	uint32_t									misa;
	/** RAM information */
#ifdef _FPGA_SPECIFIC_
	struct __attribute__((packed))
	{
		/**  */
		uintptr_t _base_address;
		/**  */
		size_t _size;
		/**  */
		struct _metal_memory_attributes _attrs;
	} iram;
#else
	metal_memory								iram;
#endif /* _FPGA_SPECIFIC_ */
	/** Consecutive internal RAM free area - start address */
	uint64_t									free_ram_start;
	/** Consecutive internal RAM free area - end address */
	uint64_t									free_ram_end;
	/** OTP information */
#ifdef _FPGA_SPECIFIC_
	struct __attribute__((packed))
	{
		/**  */
		uintptr_t _base_address;
		/**  */
		size_t _size;
		/**  */
		struct _metal_memory_attributes _attrs;
	} otp;
#else
	metal_memory								otp;
#endif /* _FPA_SPECIFIC_ */
#ifdef _WITH_GPIO_CHARAC_
	/** For GPIO toggling for GPIO0:16-GPIO0:31 */
	struct metal_gpio							*gpio0;
	/** For LEDs switching */
	struct metal_led							*led[3];
#endif /* _WITH_GPIO_CHARAC_ */
	/** Pointers on modules' context structures */
	/** Key Management */
	volatile void								*p_km_context;
	/** Platform Phase Management */
	volatile void								*p_ppm_context;
	/** Secure Boot Core Management */
	volatile void								*p_sbrm_context;
	/** Secure Flexible Loader Verification */
	volatile void								*p_slbv_context;
	/** Secure Protocol */
	volatile void								*p_sp_context;
	/** Pointers on SCL context structure */
	volatile metal_scl_t						*p_metal_sifive_scl;
	/** Pointer on SCL hash context structure */
	volatile scl_sha_ctx_t						*p_scl_hash_ctx;
	/** Buffer for has computation spreadly used in SBR - it must be aligned, mandatory for SCL */
	__attribute__((aligned(0x10))) uint8_t		digest[SHA384_BYTE_HASHSIZE];

} t_context;

/** Functions *****************************************************************/
int_pltfrm context_initialization(t_context *p_ctx);

/** Macros ********************************************************************/
#define	M_GET_OTP_ABSOLUTE_ADDR(_ctx_, _offset_) \
		((((t_context)_ctx_).otp._base_address) + _offset_)

#define M_CHANGE_ENDIANNESS_32BITS(__number__) \
											( ( ( __number__ >> 24 ) & 0x000000ff ) |\
												( ( __number__ >> 8 ) & 0x0000ff00 ) |\
												( ( __number__ << 8 ) & 0x00ff0000 ) | \
												( ( __number__ << 24 ) & 0xff000000 ) )

#define	M_WHOIS_MAX(_a_, _b_)				(( _a_ < _b_ ) ? _b_ : _a_)
#define	M_WHOIS_MIN(_a_, _b_)				(( _a_ < _b_ ) ? _a_ : _b_)

#endif /* INCLUDE_COMMON_H_ */

/******************************************************************************/
/* End Of File */
