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
 * @file slbv.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


#ifndef _SFLV_H_
#define _SFLV_H_

/** Global includes */
#include <stdint.h>
/** Other includes */
#include <common.h>
#include <errors.h>
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#define C_SLBV_BASE_ERROR        				( N_PREFIX_SLBV << C_PREFIX_OFFSET )

#define	C_SEC_HDR_ADDRESS_SIZE_32BITS			0x0101
#define	C_SEC_HDR_ADDRESS_SIZE_64BITS			0x4e4e
#define	C_SEC_HDR_ADDRESS_SIZE_128BITS			0xb2b2

#define	C_SEC_HDR_MAX_SIGNATRES					0x2
#define	C_SEC_HDR_ONE_SIGNATURE					0xED
#define	C_SEC_HDR_TWO_SIGNATURES				0x48

#define	C_SLBV_QSPI_PORT_ID						0x1
#define	C_SLBV_QSPI_BAUDRATE					100000

#define	C_SLBV_EMMC_PORT_ID						0x0

#define	GPT_GUID_SIZE							16

/** Enumerations **************************************************************/
typedef enum
{
	/**  */
	N_SLBV_ERR_MIN = C_SLBV_BASE_ERROR,
	N_SLBV_ERR_SYNC_PTRN_FAILURE = N_SLBV_ERR_MIN,
	N_SLBV_ERR_NOT_VIRGIN,
	N_SLBV_ERR_NO_FREE_LOCATION,
	N_SLBV_ERR_NO_CSK_AVAILABLE,
	N_SLBV_ERR_INVALID_SIGNATURE,
	N_SLBV_ERR_ALGO_NOT_SUPPORTED,
	N_SLBV_ERR_WRONG_KEY_SIZE,
	N_SLBV_ERR_INVAL,
	N_SLBV_ERR_APPLI_TYPE_NOT_SUPPORTED,
	N_SLBV_ERR_APPLI_TARGET_NOT_SUPPORTED,
	N_SLBV_ERR_APPLI_KEY_MISMATCH,
	N_SLBV_ERR_VERSION_MISMATCH,
	N_SLBV_ERR_HDR_VERSION_MISMATCH,
	N_SLBV_ERR_ADDR_SIZE_NOT_SUPPORTED,
	N_SLBV_ERR_CRYPTO_FAILURE,
	N_SLBV_ERR_NO_APP_REF_VERSION,
	N_SLBV_ERR_NO_BOOT_ADDRESS,
	N_SLBV_ERR_UNHANDLED_BOOT_ROUTINE,
	N_SLBV_ERR_NOT_IN_RANGE,
	N_SLBV_ERR_EXEC_NOT_IN_RANGE,
	N_SLBV_ERR_NOT_SUPPORTED,
	N_SLBV_ERR_KEY_INCOHERENCE,
	N_SLBV_ERR_BOOTDEV_NOT_SUPPORTED,
	N_SLBV_ERR_INVAL_BINARY_OFST,
	N_SLBV_ERR_BINARY_SIZE_INCOHERENCE,
	N_SLBV_ERR_NO_INTERFACE_QSPI,
	N_SLBV_ERR_NO_INTERFACE_EMMC,
	N_SLBV_ERR_QSPI_TROUBLE,
	N_SLBV_ERR_EMMC_TROUBLE,
	N_SLBV_ERR_GUID_NOT_EQUAL,
	N_SLBV_ERR_GPT_PARTITION_NOT_FOUND,
	N_SLBV_ERR_GPT_INVALID_PARTITION,
	N_SLBV_ERR_INTERFACE_NOT_INITIALIZED,
	N_SLBV_ERR_,
	N_SLBV_ERR_MAX = N_SLBV_ERR_,
	N_SLBV_ERR_COUNT

} e_slbv_error;

typedef enum
{
	/**  */
	N_SLBV_SLB_ID_S21 = 0x21,
	N_SLBV_SLB_ID_E31 = 0x31,
	N_SLBV_SLB_ID_U74 = 0x74

} e_slbv_slb_id;

/** Structures ****************************************************************/
typedef int32_t (*__fct_ptr_entry32)(void);
typedef int_pltfrm (*__fct_ptr_enrty64)(void);

#ifdef _WITH_128BITS_ADDRESSING_
typedef intmax_t (*__fct_ptr_enrty128)(void);
#endif /* _WITH_128BITS_ADDRESSING_ */

typedef struct
{
	/** Does application need decryption ? */
	uint8_t										decryption;
	/** Reference firmware version */
	uint32_t									ref_appli_version;
	/** SCR's BOOTDEV value */
	uint32_t									bootdev;
	/** Pointer on header */
	volatile t_secure_header					*p_hdr;
	/** Function pointer */
	void										(*jump_fct_ptr)(void);
	/** Boot address : where to read header of binary image */
	volatile uint_pltfrm							boot_addr;
	/** Interface of external storage */
	union
	{
		/** QSPI */
		struct metal_qspi						*qspi;
		/** eMMC */
		struct metal_emmc						*emmc;

	} boot;

} t_slbv_context;

/** Functions *****************************************************************/
int_pltfrm slbv_init(void *p_ctx, void *p_in, uint32_t length_in);
int_pltfrm slbv_shutdown(void *p_ctx);
int_pltfrm slbv_process(t_context *p_ctx);
int_pltfrm slbv_get_boot_address(t_context *p_ctx, uint_pltfrm *p_addr);
int_pltfrm slbv_get_application_version(t_context *p_ctx, uint32_t *p_version);
int_pltfrm slbv_check_slb(t_context *p_ctx, e_slbv_slb_id slb_id);

/** Macros ********************************************************************/

#endif /* _SFLV_H_ */

/******************************************************************************/
/* End Of File */
