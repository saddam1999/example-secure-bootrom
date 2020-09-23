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
 * @file otp_mapping.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _OTP_MAPPING_H_
#define _OTP_MAPPING_H_

/** Global includes */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <common.h>
/** Other includes */
/** Local includes */

/** External declarations */
extern const uint32_t otp_secure[];
extern const uint32_t otp_private[];
/** Local declarations */

/** Defines *******************************************************************/
#define	C_OTP_BASE_OFFSET						0
#ifdef _FPGA_SPECIFIC_
#define	C_OTP_PRIVATE_BASE_OFFSET				(uint_pltfrm)otp_private
#else
#define	C_OTP_PRIVATE_BASE_OFFSET				C_OTP_BASE_OFFSET
#endif /* _FPGA_SPECIFIC_ */
#define	C_OTP_BASIC_ELMNT_SIZE					sizeof(uint32_t)

#define	C_OTP_KEY_DESC_SIZE						C_OTP_BASIC_ELMNT_SIZE

/** All parameters size are in Bytes */

/** RFU - 0x0000 **************************************************************/
#define	C_OTP_RFU0_OFST							C_OTP_PRIVATE_BASE_OFFSET
#define	C_OTP_RFU0_SIZE							0x20
#define	C_OTP_RFU0_END_OFST						( C_OTP_RFU0_OFST + C_OTP_RFU0_SIZE )

/** UID - 0x0020 ***************************************************************/
#define	C_OTP_UID_OFST							C_OTP_RFU0_END_OFST
#define	C_OTP_UID_SIZE							C_UID_SIZE_IN_BYTES
#define	C_OTP_UID_END_OFST						( C_OTP_UID_OFST + C_OTP_UID_SIZE )

/** RFU - 0x0030 **************************************************************/
#define	C_OTP_RFU1_OFST							C_OTP_UID_END_OFST
#define	C_OTP_RFU1_SIZE							0x50
#define	C_OTP_RFU1_END_OFST						( C_OTP_RFU1_OFST + C_OTP_RFU1_SIZE )

/** PSK - 0x0080 **********************************************************/
#define	C_OTP_PSK_AREA_OFST						C_OTP_RFU1_END_OFST

#define	C_OTP_PSK_DESC_OFST						C_OTP_PSK_AREA_OFST
#define	C_OTP_PSK_DESC_SIZE						C_OTP_KEY_DESC_SIZE
#define	C_OTP_PSK_DESC_END_OFST					( C_OTP_PSK_DESC_OFST + C_OTP_PSK_DESC_SIZE )

/** PSK Key - 0x0084 **********************************************************/
#define	C_OTP_PSK_KEY_OFST						C_OTP_PSK_DESC_END_OFST
#define	C_OTP_PSK_KEY_SIZE						( 2 * C_EDCSA384_SIZE )
#define	C_OTP_PSK_KEY_END_OFST					( C_OTP_PSK_KEY_OFST + C_OTP_PSK_KEY_SIZE )

/** PSK certificate - 0x00e4 */
#define	C_OTP_PSK_CERT_OFST						C_OTP_PSK_KEY_END_OFST
#define	C_OTP_PSK_CERT_SIZE						( 2 * C_EDCSA384_SIZE )
#define	C_OTP_PSK_CERT_END_OFST					( C_OTP_PSK_CERT_OFST + C_OTP_PSK_CERT_SIZE )

#define	C_OTP_PSK_AREA_SIZE						( C_OTP_PSK_DESC_SIZE + C_OTP_PSK_KEY_SIZE + C_OTP_PSK_CERT_SIZE )
#define	C_OTP_PSK_AREA_END_OFST					( C_OTP_PSK_AREA_OFST + C_OTP_PSK_AREA_SIZE )

/** SUP Stimulus, BOOT_DEV - 0x0800 *******************************************/
#ifdef _FPGA_SPECIFIC_
#define	C_OTP_SECURE_BASE_OFFSET				(uint_pltfrm)otp_secure
#else
#define	C_OTP_SECURE_BASE_OFFSET				( C_OTP_BASE_OFFSET + 0x0800 )
#endif /* _FPGA_SPECIFIC_ */
/** SUP_DISABLE pattern - 0x0800 **********************************************/
#define	C_OTP_SUP_DISABLE_OFST					C_OTP_SECURE_BASE_OFFSET
#define	C_OTP_SUP_DISABLB_SIZE					C_OTP_BASIC_ELMNT_SIZE
#define	C_OTP_SUP_DISABLE_END_OFST				( C_OTP_SUP_DISABLE_OFST + C_OTP_SUP_DISABLB_SIZE )

/** Offset in bits */
#define	C_OTP_SUP_DISABLE_PATTERN_OFST			0
#define	C_OTP_SUP_DISABLE_PATTERN_MASK_NOOFST	0x3
#define	C_OTP_SUP_DISABLE_PATTERN_MASK			( C_OTP_SUP_DISABLE_PATTERN_MASK_NOOFST << C_OTP_SUP_DISABLE_PATTERN_OFST )
#define	C_OTP_SUP_DISABLE_PATTERN_NOOFST		0
#define	C_OTP_SUP_DISABLE_PATTERN				( C_OTP_SUP_DISABLE_PATTERN_NOOFST << C_OTP_SUP_DISABLE_OFST )

/** BOOT_DEV parameter - 0x0804 ***********************************************/
#define	C_OTP_BOOTDEV_OFST						C_OTP_SUP_DISABLE_END_OFST
#define	C_OTP_BOOTDEV_SIZE						C_OTP_BASIC_ELMNT_SIZE
#define	C_OTP_BOOTDEV_END_OFST					( C_OTP_BOOTDEV_OFST + C_OTP_BOOTDEV_SIZE )
/** Offset in bits */
#define	C_OTP_BOOTDEV_PATTERN_OFST				0
#define	C_OTP_BOOTDEV_PATTERN_MASK_NOOFST		0x3
#define	C_OTP_BOOTDEV_PATTERN_MASK				( C_OTP_BOOTDEV_MASK_NOOFST << C_OTP_BOOTDEV_OFST )
#define	C_OTP_BOOTDEV_QSPI_NOOFST				0x1
#define	C_OTP_BOOTDEV_EMMC_NOOFST				0x2
#define	C_OTP_BOOTDEV_RFU0_NOOFST				0x0
#define	C_OTP_BOOTDEV_RFU1_NOOFST				0x3
#define	C_OTP_BOOTDEV_PATTERN					( C_OTP_BOOTDEV_PATTERN_NOOFST << C_OTP_BOOTDEV_OFST )

/** S21_DBG_DISABLE parameter - 0x0808 ****************************************/
#define	C_OTP_S21_DBG_DISABLE_OFST				C_OTP_BOOTDEV_END_OFST
#define	C_OTP_S21_DBG_DISABLE_SIZE				C_OTP_BASIC_ELMNT_SIZE
#define	C_OTP_S21_DBG_DISABLE_END_OFST			( C_OTP_S21_DBG_DISABLE_OFST + C_OTP_S21_DBG_DISABLE_SIZE )

/** DBG_DISABLE parameter - 0x080c ********************************************/
#define	C_OTP_DBG_DISABLE_OFST					C_OTP_S21_DBG_DISABLE_END_OFST
#define	C_OTP_DBG_DISABLE_SIZE					C_OTP_BASIC_ELMNT_SIZE
#define	C_OTP_DBG_DISABLE_END_OFST				( C_OTP_DBG_DISABLE_OFST + C_OTP_DBG_DISABLE_SIZE )

/** Life Cycle - 0x0810 *******************************************************/
#define	C_OTP_LCP_OFST							C_OTP_DBG_DISABLE_END_OFST
#define	C_OTP_LCP_SIZE							C_OTP_BASIC_ELMNT_SIZE
#define	C_OTP_LCP_END_OFST						( C_OTP_LCP_OFST + C_OTP_LCP_SIZE )

/** Offset in bits */
#define	C_OTP_LCP_1_OFST						0
#define	C_OTP_LCP_1_MASK_NOOFST					0xff
#define	C_OTP_LCP_1_MASK						( C_OTP_LCP_1_MASK_NOOFST << C_OTP_LCP_1_OFST )
#define	C_OTP_LCP_1_PATTERN_NOOFST				0x51
#define	C_OTP_LCP_1_PATTERN						( C_OTP_LCP_1_PATTERN_NOOFST << C_OTP_LCP_1_OFST )

/** RMA_CSK parameter - 0x0814 ************************************************/
#define	C_OTP_RMA_PATTERN_NOOFST				0xa5


#define	C_OTP_RMA_CSK_OFST						C_OTP_LCP_END_OFST
#define	C_OTP_RMA_CSK_SIZE						C_OTP_BASIC_ELMNT_SIZE
#define	C_OTP_RMA_CSK_END_OFST					( C_OTP_RMA_CSK_OFST + C_OTP_RMA_CSK_SIZE )
/** Offset in bits */
#define	C_OTP_RMA_CSK_PATTERN_OFST				0
#define	C_OTP_RMA_CSK_PATTERN_MASK_NOOFST		0xff
#define	C_OTP_RMA_CSK_PATTERN_MASK				( C_OTP_RMA_CSK_PATTERN_MASK_NOOFST << C_OTP_RMA_CSK_PATTERN_OFST )
#define	C_OTP_RMA_CSK_PATTERN_NOOFST			C_OTP_RMA_PATTERN_NOOFST
#define	C_OTP_RMA_CSK_PATTERN					( C_OTP_RMA_CSK_PATTERN_NOOFST << C_OTP_RMA_CSK_OFST )

/** RMA_PMU parameter - 0x0818 ************************************************/
#define	C_OTP_RMA_PMU_OFST						C_OTP_RMA_CSK_END_OFST
#define	C_OTP_RMA_PMU_SIZE						C_OTP_BASIC_ELMNT_SIZE
#define	C_OTP_RMA_PMU_END_OFST					( C_OTP_RMA_PMU_OFST + C_OTP_RMA_PMU_SIZE )
/** Offset in bits */
#define	C_OTP_RMA_PMU_PATTERN_OFST				0
#define	C_OTP_RMA_PMU_PATTERN_MASK_NOOFST		0xff
#define	C_OTP_RMA_PMU_PATTERN_MASK				( C_OTP_RMA_PMU_PATTERN_MASK_NOOFST << C_OTP_RMA_PMU_PATTERN_OFST )
#define	C_OTP_RMA_PMU_PATTERN_NOOFST			~C_OTP_RMA_CSK_PATTERN_NOOFST
#define	C_OTP_RMA_PMU_PATTERN					( C_OTP_RMA_PMU_PATTERN_NOOFST << C_OTP_RMA_PMU_OFST )

/** UART configuration parameters - slot0 - 0x081c ****************************/
#define	C_OTP_UART_AREA_OFST					C_OTP_RMA_PMU_END_OFST
#define	C_OTP_UART_ELMNT_SIZE					C_OTP_BASIC_ELMNT_SIZE

#define	C_OTP_UART_CFG0_OFST					C_OTP_UART_AREA_OFST
#define	C_OTP_UART_CFG0_SIZE					C_OTP_UART_ELMNT_SIZE
#define	C_OTP_UART_CFG0_END_OFST				( C_OTP_UART_CFG0_OFST + C_OTP_UART_CFG0_SIZE )
/** UART configuration parameters - slot1 - 0x0820 */
#define	C_OTP_UART_CFG1_OFST					C_OTP_UART_CFG0_END_OFST
#define	C_OTP_UART_CFG1_SIZE					C_OTP_UART_ELMNT_SIZE
#define	C_OTP_UART_CFG1_END_OFST				( C_OTP_UART_CFG1_OFST + C_OTP_UART_CFG1_SIZE )
/** UART configuration parameters - slot2 - 0x0824 */
#define	C_OTP_UART_CFG2_OFST					C_OTP_UART_CFG1_END_OFST
#define	C_OTP_UART_CFG2_SIZE					C_OTP_UART_ELMNT_SIZE
#define	C_OTP_UART_CFG2_END_OFST				( C_OTP_UART_CFG2_OFST + C_OTP_UART_CFG2_SIZE )

#define	C_OTP_UART_TOTAL_SIZE					( C_OTP_UART_CFG0_SIZE + C_OTP_UART_CFG1_SIZE + C_OTP_UART_CFG2_SIZE )
#define	C_OTP_UART_END_OFST						( C_OTP_UART_AREA_OFST + C_OTP_UART_TOTAL_SIZE )

#define	C_OTP_LAST_UART_OFST					( C_OTP_UART_END_OFST - C_OTP_UART_ELMNT_SIZE )
#define C_OTP_NB_UART_SLOTS						( ( C_OTP_UART_END_OFST - C_OTP_UART_AREA_OFST ) / C_OTP_UART_ELMNT_SIZE )

#define C_OTP_UART_SLOT_MAX						( C_OTP_NB_UART_SLOTS - 1 )

/** CSK Rule Pattern - 0x0828 *************************************************/
#define	C_OTP_CSK_RULE_PATTERN_OFST				C_OTP_UART_END_OFST
#define	C_OTP_CSK_RULE_PATTERN_SIZE				C_OTP_CSK_DESC_ELMT_SIZE
#define	C_OTP_CSK_RULE_PATTERN_END_OFST			( C_OTP_CSK_RULE_PATTERN_OFST + C_OTP_CSK_RULE_PATTERN_SIZE )

/** CSK - 0x082c **************************************************************/
#define	C_OTP_CSK_AREA_OFST						C_OTP_CSK_RULE_PATTERN_END_OFST

#define	C_OTP_CSK_DESC_ELMT_SIZE				C_OTP_KEY_DESC_SIZE
#define	C_OTP_CSK_KEY_SIZE						( 2 * C_EDCSA384_SIZE )
#define	C_OTP_CSK_CERT_SIZE						C_EDCSA384_SIZE

#define	C_OTP_CSK_AERA_SIZE						( C_OTP_CSK_DESC_ELMT_SIZE +\
													C_OTP_CSK_KEY_SIZE +\
													C_OTP_CSK_CERT_SIZE )

/** CSK descriptor - slot0 - 0x082c *******************************************/
#define	C_OTP_CSK0_DESC_OFST					C_OTP_CSK_AREA_OFST
#define	C_OTP_CSK0_DESC_SIZE					C_OTP_CSK_DESC_ELMT_SIZE
#define	C_OTP_CSK0_DESC_END_OFST				( C_OTP_CSK0_DESC_OFST + C_OTP_CSK0_DESC_SIZE )
/** CSK - slot0 - 0x0830 */
#define	C_OTP_CSK0_KEY_OFST						C_OTP_CSK0_DESC_END_OFST
#define	C_OTP_CSK0_KEY_SIZE						C_OTP_CSK_KEY_SIZE
#define	C_OTP_CSK0_KEY_END_OFST					( C_OTP_CSK0_KEY_OFST + C_OTP_CSK0_KEY_SIZE )
/** CSK certificate - slot0 - 0x0890 */
#define	C_OTP_CSK0_CERT_OFST					C_OTP_CSK0_KEY_END_OFST
#define	C_OTP_CSK0_CERT_SIZE					C_OTP_CSK_CERT_SIZE
#define	C_OTP_CSK0_CERT_END_OFST				( C_OTP_CSK0_CERT_OFST + C_OTP_CSK0_CERT_SIZE )

/** CSK descriptor - slot1 - 0x08c0 *******************************************/
#define	C_OTP_CSK1_DESC_OFST					C_OTP_CSK0_CERT_END_OFST
#define	C_OTP_CSK1_DESC_SIZE					C_OTP_CSK_DESC_ELMT_SIZE
#define	C_OTP_CSK1_DESC_END_OFST				( C_OTP_CSK1_DESC_OFST + C_OTP_CSK1_DESC_SIZE )
/** CSK - slot1 - 0x08c4 */
#define	C_OTP_CSK1_KEY_OFST						C_OTP_CSK1_DESC_END_OFST
#define	C_OTP_CSK1_KEY_SIZE						C_OTP_CSK_KEY_SIZE
#define	C_OTP_CSK1_KEY_END_OFST					( C_OTP_CSK1_KEY_OFST + C_OTP_CSK1_KEY_SIZE )
/** CSK certificate - slot1 - 0x0924 */
#define	C_OTP_CSK1_CERT_OFST					C_OTP_CSK1_KEY_END_OFST
#define	C_OTP_CSK1_CERT_SIZE					C_OTP_CSK_CERT_SIZE
#define	C_OTP_CSK1_CERT_END_OFST				( C_OTP_CSK1_CERT_OFST + C_OTP_CSK1_CERT_SIZE )

/** CSK descriptor - slot2 - 0x0954 *******************************************/
#define	C_OTP_CSK2_DESC_OFST					C_OTP_CSK1_CERT_END_OFST
#define	C_OTP_CSK2_DESC_SIZE					C_OTP_CSK_DESC_ELMT_SIZE
#define	C_OTP_CSK2_DESC_END_OFST				( C_OTP_CSK2_DESC_OFST + C_OTP_CSK2_DESC_SIZE )
/** CSK - slot2 - 0x0958 */
#define	C_OTP_CSK2_KEY_OFST						C_OTP_CSK2_DESC_END_OFST
#define	C_OTP_CSK2_KEY_SIZE						C_OTP_CSK_KEY_SIZE
#define	C_OTP_CSK2_KEY_END_OFST					( C_OTP_CSK2_KEY_OFST + C_OTP_CSK2_KEY_SIZE )
/** CSK certificate - slot2 - 0x09b8 */
#define	C_OTP_CSK2_CERT_OFST					C_OTP_CSK2_KEY_END_OFST
#define	C_OTP_CSK2_CERT_SIZE					C_OTP_CSK_CERT_SIZE
#define	C_OTP_CSK2_CERT_END_OFST				( C_OTP_CSK2_CERT_OFST + C_OTP_CSK2_CERT_SIZE )

#define	C_OTP_CSK_END_OFST						C_OTP_CSK2_CERT_END_OFST

#define	C_OTP_LAST_CSK_OFST						( C_OTP_CSK_END_OFST - C_OTP_CSK_AERA_SIZE )
#define C_OTP_NB_CSK_SLOTS						( ( C_OTP_CSK_END_OFST - C_OTP_CSK_AREA_OFST ) / C_OTP_CSK_AERA_SIZE )

#define C_OTP_CSK_SLOT_MAX						( C_OTP_NB_CSK_SLOTS - 1 )

/** Application's Reference Version - 0x09e8 **********************************/
#define	C_OTP_APP_REFV_AREA_OFST				C_OTP_CSK_END_OFST
#define	C_OTP_APP_REFV_ELMNT_SIZE				C_OTP_BASIC_ELMNT_SIZE

/**  Offset 0x09ec */
#define	C_OTP_APP_REFV1_OFST					C_OTP_APP_REFV_AREA_OFST
#define	C_OTP_APP_REFV1_SIZE					C_OTP_APP_REFV_ELMNT_SIZE
#define	C_OTP_APP_REFV1_END_OFST				( C_OTP_APP_REFV1_OFST + C_OTP_APP_REFV1_SIZE )
/**  Offset 0x09f0 */
#define	C_OTP_APP_REFV2_OFST					C_OTP_APP_REFV1_END_OFST
#define	C_OTP_APP_REFV2_SIZE					C_OTP_APP_REFV_ELMNT_SIZE
#define	C_OTP_APP_REFV2_END_OFST				( C_OTP_APP_REFV2_OFST + C_OTP_APP_REFV2_SIZE )
/**  Offset 0x09f4 */
#define	C_OTP_APP_REFV3_OFST					C_OTP_APP_REFV2_END_OFST
#define	C_OTP_APP_REFV3_SIZE					C_OTP_APP_REFV_ELMNT_SIZE
#define	C_OTP_APP_REFV3_END_OFST				( C_OTP_APP_REFV3_OFST + C_OTP_APP_REFV3_SIZE )
/**  Offset 0x09f8 */
#define	C_OTP_APP_REFV4_OFST					C_OTP_APP_REFV3_END_OFST
#define	C_OTP_APP_REFV4_SIZE					C_OTP_APP_REFV_ELMNT_SIZE
#define	C_OTP_APP_REFV4_END_OFST				( C_OTP_APP_REFV4_OFST + C_OTP_APP_REFV4_SIZE )
/**  Offset 0x09fc */
#define	C_OTP_APP_REFV5_OFST					C_OTP_APP_REFV4_END_OFST
#define	C_OTP_APP_REFV5_SIZE					C_OTP_APP_REFV_ELMNT_SIZE
#define	C_OTP_APP_REFV5_END_OFST				( C_OTP_APP_REFV5_OFST + C_OTP_APP_REFV5_SIZE )
/**  Offset 0x0a00 */
#define	C_OTP_APP_REFV6_OFST					C_OTP_APP_REFV5_END_OFST
#define	C_OTP_APP_REFV6_SIZE					C_OTP_APP_REFV_ELMNT_SIZE
#define	C_OTP_APP_REFV6_END_OFST				( C_OTP_APP_REFV6_OFST + C_OTP_APP_REFV6_SIZE )

#define	C_OTP_APP_REFV_END_OFST					C_OTP_APP_REFV6_END_OFST

#define	C_OTP_LAST_APP_REFV_OFST				( C_OTP_APP_REFV_END_OFST - C_OTP_APP_REFV_ELMNT_SIZE )
#define C_OTP_NB_APP_REFV_SLOTS					( ( C_OTP_APP_REFV_END_OFST - C_OTP_APP_REFV_AREA_OFST ) / C_OTP_APP_REFV_ELMNT_SIZE )

#define C_OTP_APP_REFV_SLOT_MAX					( C_OTP_NB_APP_REFV_SLOTS - 1 )

/** Patch Storage Area ********************************************************/
#define	C_OTP_PATCH_OFFSET						0

#define	C_OTP_PATCH_SIZE						( 1 * C_GENERIC_KILO )

/** Enumerations **************************************************************/

/** Structures ****************************************************************/

/** Functions *****************************************************************/

/** Macros ********************************************************************/

#endif /* _OTP_MAPPING_H_ */

/******************************************************************************/
/* End Of File */
