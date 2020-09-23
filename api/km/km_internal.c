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
 * @file km_internal.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


/** Global includes */
#include <common.h>
#include <errors.h>
#include <otp_mapping.h>
/** Other includes */
/** Local includes */
#include <km.h>
#include <km_internal.h>

/** External declarations */
extern t_km_context km_context;
/** Local declarations */
/** Descriptor for both STK and SSK key **************************************/
__attribute__((section(".rodata"))) const uint8_t ssk_descriptor[sizeof(uint32_t)] =
{
		/** Algorithm - ECDSA -> A7 */
		N_KM_ALGO_ECDSA384,
		/** SKID - None */
		N_KM_KEYID_NOKEY,
		/** ECDSA384 number of bits -> 384 -> 0x0180 */
		0x80,
		0x01

};
/** SiFive Signing Key - Test version - ECDSA384 ************************/
__attribute__((section(".rodata"))) const uint8_t ssk[2 * C_EDCSA384_SIZE] =
{
		/** public key X coordinate */
		0xa6,0x90,0xac,0x1c,0xe1,0x1e,0xa7,0x1a,0xcc,0xaa,0x6a,0xde,0xc5,0x15,0x95,0x9a,
		0xd7,0xf2,0xfd,0x80,0x0c,0x68,0xb0,0x7d,0x0b,0xc5,0x33,0xdd,0x00,0x4d,0xa8,0x08,
		0xb1,0x70,0x6c,0x4a,0x96,0x69,0x6f,0x99,0x90,0xed,0x8c,0x24,0x01,0x5f,0xf2,0xc2,
		/** public key Y coordinate */
		0x1f,0x53,0xb0,0x16,0xa7,0x67,0x2a,0xca,0xe2,0xbc,0x96,0xfa,0xb9,0x18,0x1c,0x8d,
		0x05,0x04,0x7d,0x4e,0x8c,0xba,0x09,0xb7,0x49,0x10,0x27,0x26,0xc1,0x82,0x77,0xc3,
		0xe9,0x66,0x0e,0xe0,0xb4,0x12,0x8c,0x93,0xbc,0xda,0xe7,0x50,0x8f,0xcd,0x7e,0xa5

};

#ifdef _FPGA_SPECIFIC_
#endif /**  */

/******************************************************************************/
/* End Of File */
