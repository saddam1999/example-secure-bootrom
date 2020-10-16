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
 * @file sp.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _SP_H_
#define _SP_H_

/** Global includes */
#include <errors.h>
/** Other includes */
#include <common.h>
#include <errors.h>
#include <km.h>
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
/** SP errors base */
#define C_SP_BASE_ERROR        					( N_PREFIX_SP << C_PREFIX_OFFSET )

/** UART0 is the default UART ID */
#define	C_SP_SUP_BUS_UART_ID					0

/** Enumerations **************************************************************/
/** SP errors list */
typedef enum
{
	/* Common errors */
	N_SP_ERR_MIN = C_SP_BASE_ERROR,
	/** Error Code: SP module not initialized */
	N_SP_ERR_NOT_INITIALIZED = N_SP_ERR_MIN,
	/** Error Code: Wanted protocol does not exist */
	N_SP_ERR_NO_PROTOCOL,
	/** Communication errors **************************************************/
	/** Bus communication interruption cannot be retrieved */
	N_SP_ERR_SUP_CANT_RETRIEVE_IRQ_PTR,
	/** Handler for communication bus cannot be registered */
	N_SP_ERR_SUP_CANT_REGISTER_IRQ_HANDLER,
	/* SUP errors *************************************************************/
	/** SUP can not be initialized */
	N_SP_ERR_SUP_NOT_INITIALIZED,
	/** No more space left for SUP */
	N_SP_ERR_SUP_NO_MORE_MEMORY,
	/** UID does not match */
	N_SP_ERR_SUP_UID_NO_MATCH,
	/** ECC recovery failed */
	N_SP_ERR_SUP_WRONG_ECC,
	/** Segment command is not supported */
	N_SP_ERR_SUP_WRONG_CMD,
	/** Wrong UID passed in packet */
	N_SP_ERR_SUP_WRONG_UID,
	/** Wrong length for command */
	N_SP_ERR_SUP_WRONG_CMD_LENGTH,
	/** SUP connection not triggered */
	N_SP_ERR_SUP_NO_SESSION,
	/** Connection for SUP timed out */
	N_SP_ERR_SUP_CNX_TIMEOUT,
	/** Packet type unknown */
	N_SP_ERR_SUP_NET_BAD_CONFIG,
	/** Session Identifier doesn't match */
	N_SP_ERR_SUP_NET_WRONG_SESSION,
	/** Packet number is not accurate */
	N_SP_ERR_SUP_NET_WRONG_PACKET_NB,
	/** Payload length shouldn't be below minimum value */
	N_SP_ERR_SUP_PAYLOAD_SIZE_TOO_SMALL,
	/** Unknown error in networking */
	N_SP_ERR_SUP_NET_UNKNOWN,
	/** Segments too numerous */
	N_SP_ERR_SUP_TOO_MANY_SEGS,
	/** Segments number in packet exceeds expected one */
	N_SP_ERR_SUP_EXCEED_PKT_SEG,
	/** Parameters don't match */
	N_SP_ERR_SUP_BAD_PARAMS,
	/** Signature number doesn't match expected one */
	N_SP_ERR_SUP_SIG_NB_DONT_MATCH,
	/** Segment is not free */
	N_SP_ERR_SUP_SEG_NOT_FREE,
	/** SUP window(s) should not be opened */
	N_SP_ERR_SUP_NO_SESSION_ALLOWED,
	/** Command can not be proceeded */
	N_SP_ERR_SUP_CANT_PROCEEED,
	/** Communication port not handled */
	N_SP_ERR_SUP_COM_PORT_NOT_HANDLED,
	/** Synchronization pattern is not present in header */
	N_SP_ERR_SUP_NO_SYNC,
	/** Cryptographic related error */
	N_SP_ERR_SUP_CRYPTO_FAILURE,
	/** Problem in sending process */
	N_SP_ERR_SUP_TX_COMMUNICATION_FAILURE,
	/** SUP packet is not granted on platform */
	N_SP_ERR_SUP_PACKET_REJECTED,
	/* SUP Applet errors ******************************************************/
	/** No applet registered */
	N_SP_ERR_SUP_APLT_NO_REGISTERED,
	/** Not handled by applet */
	N_SP_ERR_SUP_APLT_NOT_HANDLED,
	/** Jump address does not fit memory area */
	N_SP_ERR_SUP_JUMP_ADDR_FAILURE,
	/* SUP application command errors *****************************************/
	/** Compare failed */
	N_SP_ERR_SUP_APPLI_COMPARE_FAILURE,
	/* SUP command specific errors */
	/** Can't proceed WRITE-CSK command */
	N_SP_ERR_SUP_WRITEKEY_FAILED,
	/** Expect signing key does not match referenced one */
	N_SP_ERR_SUP_KEY_MISMATCH,
	/** No free slot */
	N_SP_ERR_SUP_NO_FREE_SLOT,
	/** Algorithm does not match */
	N_SP_ERR_SUP_ALGO_MISMATCH,
	/** Key is not supported */
	N_SP_ERR_SUP_KEY_NOT_SUPPORTED,
	/** Command not supported */
	N_SP_ERR_SUP_CMD_NOT_SUPPORTED,
	/** Key verification failed before use at SUP session */
	N_SP_ERR_SUP_KEY_VERIF_FAILED,
	/** Platform reset expected */
	N_SP_ERR_RESET_PLATFORM,
	/** Platform shutdown expected */
	N_SP_ERR_SHUTDOWN_PLATFROM,
	/**  */
	/* Common errors (bis) ****************************************************/
	/** Error Code: Generic error for unknown behavior */
	N_SP_ERR_UNKNOWN,
	N_SP_ERR_MAX = N_SP_ERR_UNKNOWN

} e_sp_error;

/** Number of errors for this module */
#define	C_SP_ERR_COUNT							( N_SP_ERR_MAX - N_SP_ERR_MIN )

typedef enum
{
	/** Minimal value */
	N_SP_KEY_MIN = 0,
	N_SP_KEY_STK,
	N_SP_KEY_STK_UID,
	N_SP_KEY_SSK_CSK,
	N_SP_KEY_SSK_CSK_UID,
	/** Maximal value */
	N_SP_KEY_MAX = N_SP_KEY_SSK_CSK_UID,
	N_SP_KEY_COUNT

} e_sp_key_session;

typedef enum
{
	/** Minimal value */
	N_SP_MODE_MIN = 0xa5a55a5a,
	N_SP_MODE_NORMAL = N_SP_MODE_MIN,
	N_SP_MODE_RMA = 0x3c3cc3c3,
	N_SP_MODE_MAX = N_SP_MODE_RMA

} e_sp_sup_mode;


/** Structures ****************************************************************/


/** Functions *****************************************************************/
int_pltfrm sp_init(void *p_ctx, void *p_in, uint32_t length_in);
int_pltfrm sp_shutdown(void *p_ctx);
int_pltfrm sp_launch_sup(t_context *p_ctx, e_km_keyid key_session);


/** Macros ********************************************************************/

#endif /* _SP_H_ */

/******************************************************************************/
/* End Of File */
