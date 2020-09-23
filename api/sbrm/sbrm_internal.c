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
 * @file sbrm_internal.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


/** Global includes */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errors.h>
#include <otp_mapping.h>
#include <api/scl_api.h>
#include <api/hardware/scl_hca.h>
#include <api/hash/sha.h>
/** Other includes */
#include <km.h>
#include <pi.h>
#include <ppm.h>
#include <sbrm.h>
#include <sp.h>
#include <slbv.h>
/** Local includes */


/** External declarations */
extern volatile t_sbrm_context sbrm_context;
/** Local declarations */
#ifdef _FPGA_SPECIFIC_
__attribute__((section(".otp_mapping.data"),aligned(0x10))) const uint32_t otp_private[]=
{
		/** Offset 0x0000 - LOCK_PRIVATE_FUSE, NO_PMU_DBG_BOOT, etc ...*/
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0004 - FBDIV_MAX 1 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0008 - FBDIV_MAX 2 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x000c - SKU */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0010 - SAMPLE_ID */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0014 - VERSION */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0018 - TM_DISABLE */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0020 - UID */
		0xcafefade,
		0xdeadbeef,
		0xa55a3cc3,
		0x9669f00f,
		/** Offset 0x0030 - PLL Config */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0040 - PLL Config */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0050 - PLL Config */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0060 - PLL Config */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0070 - PLL Config */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
#ifdef _WITH_TEST_PSK_
		/** Offset 0x0080 - PSK Descriptor */
		0x01802ca7,
		/** Offset 0x0084 - PSK public key */
		0x02f4df8e,
		0x9cce3ad9,
		0x0a1d7eec,
		0x922f57e4,
		0x2bc19ca2,
		0xeb928ac7,
		0x9a889512,
		0x56a51b56,
		0x1f2616b4,
		0xed6bb3d2,
		0xf39c599f,
		0x54291509,
		0xa51af599,
		0x54c5ad9a,
		0x40cefacc,
		0xb4ae1c0a,
		0x0d3b8a00,
		0xa6504b8b,
		0x9517fa86,
		0x0ebff0ec,
		0x02df3114,
		0x8613803d,
		0x123e2f67,
		0xc7f6aed8,
		/** Offset 0x00e4 - PSK signature */
		0xeacd0a98,
		0xa9852f42,
		0x0fca841f,
		0x271b5143,
		0xbb302649,
		0x2cb22c20,
		0x4ebca324,
		0x10d4eacc,
		0xfd3575c0,
		0xdf9ab389,
		0x7ae8ea3a,
		0x85f2517c,
		0x758bde12,
		0xfee3a30d,
		0x710e922e,
		0xab8370f5,
		0xc18d1044,
		0xb045560f,
		0xa6f5c02a,
		0x8e188811,
		0xf9252b56,
		0xc963bb68,
		0xdbfbf74c,
		0x8f1ba61e
#else
		/** Offset 0x0080 - PSK Descriptor */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0084 - PSK public key */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x00e4 - PSK signature */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS
#endif /* _WITH_PSK_ */

};

__attribute__((section(".otp_mapping.data"),aligned(0x10))) const uint32_t otp_secure[]=
{
		/** Offset 0x0800 - SUP_DIABLE, BOOT_DEV, etc ... */
		/** SUP_DISABLE :
		 * off -> bit0 - 0, bit1 - 0
		 * on -> bit0 - 1, bit1 - 1
		 * RFU -> other values
		 *  */
//		0xfffffff4,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0804 - BootDev */
//		C_PATTERN_VIRGIN_32BITS,
		/** QSPI - 0xfffffff5
		 * eMMC - 0xfffffffe
		 * RFU - Other values */
		0xfffffff5,
		/** Offset 0x0808 - S21_DBG_DISABLE */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x080c - DBG_DISABLE */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0810 - Phase #1 */
#if defined(_LIFE_CYCLE_PHASE1_)
		C_OTP_LCP_1_PATTERN,
#else
		C_PATTERN_VIRGIN_32BITS,
#endif /* _LIFE_CYCLE_PHASE1_ */
		/** Offset 0x0814 - RMA_CSK */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0818 - RMA_PMU */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x081c - UART Configuration slot 1 */
		/** Baudrate -
		 * 115200 -> 0x0001c200
		 * 288000 -> 0x00046500 */
//		0x00012c00,
//		0x00046500,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0820 - UART Configuration slot 2 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0824 - UART Configuration slot 3 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0828 - CSK rule pattern */
#ifdef _WITH_CSK_RULE_PATTERN_
		0xa5a55a5a,
#else
		C_PATTERN_VIRGIN_32BITS,
#endif /* _WITH_CSK_RULE_PATTERN_ */
#ifdef _WITH_TEST_CSK_
		/** Offset 0x082c - CSK descriptor slot 1*/
		0x01802ca7,
		/** Offset 0x0830 - CSK slot 1 */
		0x3c319070,
		0x309c18d8,
		0x9d5abf05,
		0xacd0e753,
		0xd273800a,
		0x7a47675e,
		0xdec2c214,
		0x17f4605d,
		0x12f2c16d,
		0x9213faf7,
		0x43195437,
		0x2c346171,
		/** Public key Y coordinate */
		0xce7f22a6,
		0x51ab98e2,
		0x4299a8b6,
		0xa0005247,
		0x1d486a44,
		0x12e61984,
		0x08318eda,
		0xc809892c,
		0xcda52a6d,
		0x8acd729f,
		0x678fdd61,
		0x8a15a579,
		/* Offset 0x0890 - CSK's hash slot1 */
		0x02A740AF,
		0x4D857F95,
		0xC5C2222A,
		0xD439AA57,
		0xD246AFED,
		0x2A4EEA41,
		0xD54A7F31,
		0x5E656F6B,
		0xE346C842,
		0x2C173571,
		0xBC665A32,
		0x82929E81,
#else
		/** Offset 0x082c - CSK descriptor slot 1 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0830 - CSK slot 1 */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/* Offset 0x0890 - CSK's hash slot 1 */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
#endif /* _WITH_TEST_CSK_ */
		/** Offset 0x08c0 - CSK descriptor slot 2 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x08c4 - CSK slot 2 */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0924 - CSK's hash slot1 2*/
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0954 - CSK descriptor slot 3 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x0958 - CSK slot 3 */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09b8 - CSK's hash slot 3 */
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09e8 - FSBL version slot 1 */
#ifdef _WITH_FIRMWARE_VERSION_
		0x00010002,
		/** Offset 0x09ec - FSBL version slot 2 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09f0 - FSBL version slot 3 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09f4 - FSBL version slot 4 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09f8 - FSBL version slot 5 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09fc - FSBL version slot 6 */
		C_PATTERN_VIRGIN_32BITS
#else
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09ec - FSBL version slot 2 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09f0 - FSBL version slot 3 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09f4 - FSBL version slot 4 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09f8 - FSBL version slot 5 */
		C_PATTERN_VIRGIN_32BITS,
		/** Offset 0x09fc - FSBL version slot 6 */
		C_PATTERN_VIRGIN_32BITS
#endif /* _WITH_FIRMWARE_VERSION_ */
		/** Offset 0x0a00 - */
};
#endif /* _FPGA_SPECIFIC_ */

/******************************************************************************/
void sbrm_set_power_mode(uint32_t power_mode)
{
	/**  */
	switch( power_mode )
	{
		case 0:
			/**  */
			break;
		default:
			/** Shutdown mode */
			break;
	}
	/** End Of Function */
	return;
}

/******************************************************************************/
int_pltfrm sbrm_selftest(t_context *p_ctx)
{
#ifdef _WITHOUT_SELFTESTS_
	return NO_ERROR;
#else
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sbrm_selftest_out;
	}
//	/** Call KM module initialization function, it's where SCL initialization
//	 * is located */
//	err = p_ctx->p_km_fct_ptr->initialize_fct(p_ctx, NULL, 0);
//	if ( err )
//	{
//		/** AES tests failed, can't trust platform */
//		err = N_SBRM_ERR_AES_TEST_FAILURE;
//		goto sbrm_selftest_out;
//	}
	/** Call ECDSA selftest */
//	err = scl_ecdsa_p384r1_sha384_selftest();
//	if ( SCL_OK != err )
//	{
//		/** ECDSA tests failed, can't trust platform */
//		err = N_SBRM_ERR_ECDSA_TEST_FAILURE;
//	}
//	else
//	{
		/** No error */
		err = NO_ERROR;
//	}
sbrm_selftest_out:
	/** End Of Function */
	return err;
#endif /* _WITHOUT_SELFTESTS_ */
}

/******************************************************************************/
int_pltfrm sbrm_compute_crc(uint32_t *p_crc, uint8_t *p_data, uint32_t size)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint32_t									tmp = 0;
	uint32_t									i;

	/** Check input pointer */
	if( !p_crc || !p_data )
	{
		/** Pointers should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !size )
	{
		/** There should be some data to process */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Process data */
		tmp = ~*p_crc;
		/** Computation loop */
		for( i = 0;i < size;i++ )
		{
			/**  */
			tmp = ( tmp >> 8 ) ^ sbrm_context.crc_ref_table[( tmp & 0xff ) ^ p_data[i]];
		}
		/** Set CRC */
		*p_crc = ~tmp;
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/

/* End Of File */
