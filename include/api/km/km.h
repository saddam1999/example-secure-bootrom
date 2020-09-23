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
 * @file km.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


#ifndef _KM_H_
#define _KM_H_

/** Global includes */
#include <errors.h>
#include <common.h>
#include <otp_mapping.h>
/** Other includes */
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#define C_KM_BASE_ERROR        					( N_PREFIX_KM << C_PREFIX_OFFSET )

#define	C_KM_CSK_DESCR_ALGO_OFST				0
#define	C_KM_CSK_DESCR_ALGO_MASK_NOOFST			0xff
#define	C_KM_CSK_DESCR_ALGO_MASK				( C_KM_CSK_DESCR_ALGO_MASK_NOOFST << C_KM_CSK_DESCR_ALGO_OFST )
#define	C_KM_CSK_DESCR_ALGO_SIZE				8

#define	C_KM_CSK_DESCR_SKID_OFST				( C_KM_CSK_DESCR_ALGO_OFST + C_KM_CSK_DESCR_ALGO_SIZE )
#define	C_KM_CSK_DESCR_SKID_MASK_NOOFST			0xff
#define	C_KM_CSK_DESCR_SKID_MASK				( C_KM_CSK_DESCR_SKID_MASK_NOOFST << C_KM_CSK_DESCR_SKID_OFST )
#define	C_KM_CSK_DESCR_SKID_SIZE				8

/** Key size is in bits, so don't forget to divide size by 8 to have Byte size */
#define	C_KM_CSK_DESCR_KEY_SIZE_OFST			( C_KM_CSK_DESCR_SKID_OFST + C_KM_CSK_DESCR_SKID_SIZE )
#define	C_KM_CSK_DESCR_KEY_SIZE_MASK_NOOFST		0xffff
#define	C_KM_CSK_DESCR_KEY_SIZE_MASK			( C_KM_CSK_DESCR_KEY_SIZE_MASK_NOOFST << C_KM_CSK_DESCR_KEY_SIZE_OFST )
#define	C_KM_CSK_DESCR_KEY_SIZE_SIZE			16

#define	C_KM_CSK_DESCR_KEY_SIZE_IN_BYTES		( C_KM_CSK_DESCR_ALGO_SIZE + C_KM_CSK_DESCR_SKID_SIZE + C_KM_CSK_DESCR_KEY_SIZE_SIZE )

#define	C_KM_KEY_BUFFER_MAX_SIZE				( C_KM_CSK_DESCR_KEY_SIZE_IN_BYTES + C_SIGNATURE_MAX_SIZE +\
													C_KM_CSK_DESCR_KEY_SIZE_IN_BYTES + C_SIGNATURE_MAX_SIZE +\
													C_SIGNATURE_MAX_SIZE )

#define	C_KM_ARGVARGC_BUFFER_MAX_SIZE			( 0x100 + ( 3 * sizeof(uint32_t) ) )

/** Enumerations **************************************************************/
typedef enum
{
	/**  */
	N_KM_ERR_MIN = C_KM_BASE_ERROR,
	N_KM_ERR_NO_INDEX = N_KM_ERR_MIN,
	N_KM_ERR_NOT_VIRGIN,
	N_KM_ERR_NO_FREE_LOCATION,
	N_KM_ERR_NO_CSK,
	N_KM_ERR_NO_CUK,
	N_KM_ERR_NO_PSK,
	N_KM_ERR_NO_REF_KEY,
	N_KM_ERR_NO_VALID_KEY,
	N_KM_ERR_WRONG_REF_KEY,
	N_KM_ERR_CSK_INVALID,
	N_KM_ERR_CUK_INVALID,
	N_KM_ERR_PSK_INVALID,
	N_KM_ERR_NO_KEY,
	N_KM_ERR_INVALID_KEY,
	N_KM_ERR_INVALID_SIGNATURE,
	N_KM_ERR_INVALID_HASH,
	N_KM_ERR_ALGO_NOT_SUPPORTED,
	N_KM_ERR_DESCRIPTOR_FAILURE,
	N_KM_ERR_VERIFKEY_NOT_SUPPORTED,
	N_KM_ERR_WRONG_KEY_SIZE,
	N_KM_ERR_INVAL,
	N_KM_ERR_SCL_INITIALIZATION_FAILURE,
	N_KM_ERR_KEY_RETRIEVAL_FAILURE,
	N_KM_ERR_SCL_PROBLEM,
	N_KM_ERR_WRONG_SLOT,
	N_KM_ERR_,
	N_KM_ERR_MAX = N_KM_ERR_,
	N_KM_ERR_COUNT

} e_km_error;

/** Supported algorithms */
typedef enum
{
	/**  */
	N_KM_ALGO_MIN = 0,
#ifdef _SUPPORT_ALGO_AES_128_
	N_KM_ALGO_AES128,
#endif /* _SUPPORT_ALGO_AES_128_ */
#ifdef _SUPPORT_ALGO_AES_256_
	N_KM_ALGO_AES256,
#endif /* _SUPPORT_ALGO_AES_256_ */
#ifdef _SUPPORT_ALGO_RSA2048_
	N_KM_ALGO_RSA2048,
#endif /* _SUPPORT_ALGO_RSA2048_ */
#ifdef _SUPPORT_ALGO_RSA4096_
	N_KM_ALGO_RSA4096,
#endif /* _SUPPORT_ALGO_RSA4096_ */
#ifdef _SUPPORT_ALGO_ECDSA256_
	N_KM_ALGO_ECDSA256,
#endif /* _SUPPORT_ALGO_ECDSA256_ */
#ifdef _SUPPORT_ALGO_ECDSA384_
	N_KM_ALGO_ECDSA384 = 0xa7,
#endif /* _SUPPORT_ALGO_ECDSA384_ */
	N_KM_ALGO_NONE = C_PATTERN_VIRGIN_8BITS,
	N_KM_ALGO_MAX = N_KM_ALGO_NONE,

} e_km_support_algos;

/** SBR key identifier */
typedef enum
{
	/**  */
	N_KM_KEYID_MIN = 0,
	N_KM_KEYID_STK = N_KM_KEYID_MIN,
	N_KM_KEYID_SSK = 0x2c,
	N_KM_KEYID_CUK = 0x5e,
	N_KM_KEYID_PSK = 0x7e,
	N_KM_KEYID_CSK = 0x84,
	N_KM_KEYID_PREVIOUS = 0xd7,
	/** Not relevant */
	N_KM_KEYID_MAX,
	N_KM_KEYID_NOKEY = 0xff

} e_km_keyid;

/** Key index in KM structure */
typedef enum
{
	/**  */
	N_KM_INDEX_MIN = 0,
	N_KM_INDEX_PSK = N_KM_INDEX_MIN,
	N_KM_INDEX_CUK,
	N_KM_INDEX_CSK,
	N_KM_INDEX_MAX = N_KM_INDEX_CSK,
	N_KM_INDEX_COUNT

} e_km_key_index;

/** Slots number for keys */
typedef enum
{
	/**  */
	N_KM_NB_SLOTS_MIN = 0,
	K_KM_SLOT_0 = N_KM_NB_SLOTS_MIN,
	K_KM_SLOT_1,
	K_KM_SLOT_2,
	K_KM_SLOT_MAX = K_KM_SLOT_2,
	K_KM_SLOT_COUNT,
	K_KM_SLOT_NOT_SET = 0xff

} e_km_slob_nb;


/** Structures ****************************************************************/
typedef struct __attribute__((packed))
{
	/** Algorithm */
	uint8_t										algo;
	/** Signing key identifier */
	uint8_t										sign_key_id;
	/** Key size in bits */
	uint16_t									key_size_bits;
	/** Key public part */
	uint8_t										key[2 * C_EDCSA384_SIZE];
	/** Key certificate */
	uint8_t										certificate[2 * C_EDCSA384_SIZE];

} t_key_data;

typedef union __attribute__((packed))
{
	/** WRITE-CSK */
	t_key_data									write_csk;

} t_cmd_csk;


#if defined(_SUPPORT_ALGO_ECDSA256_) || defined(_SUPPORT_ALGO_ECDSA384_ )
typedef struct
{
	/** X */
	uint8_t										*p_x;
	/** Y */
	uint8_t										*p_y;

} t_km_key_ecdsa;
#endif /* ECDSA */

#if defined(_SUPPORT_ALGO_RSA2048_) || defined(_SUPPORT_ALGO_RSA4096_ )
typedef struct
{
	/** Modulus */
	uint8_t										*p_modulus;
	/** Exponent */
	uint8_t										*p_exponent;
} t_km_key_rsa;
#endif /* RSA */


typedef struct
{
	/** Key's descriptor */
	uint32_t									*p_descriptor;
#if defined(_SUPPORT_ALGO_ECDSA256_) || defined(_SUPPORT_ALGO_ECDSA384_ )
	/** Key public part */
	t_km_key_ecdsa								ecdsa;
	/** Key certificate */
	t_km_key_ecdsa								certificate;
#endif /* ECDSA */
#if defined(_SUPPORT_ALGO_RSA2048_) || defined(_SUPPORT_ALGO_RSA4096_ )
	/** Key public part */
	t_km_key_rsa								rsa;
	/** Key certificate */
	t_km_key_rsa								certificate;
#endif /* RSA */

} t_km_key;

typedef struct __attribute__((packed))
{
	/** Pointer on current key to be used in SUP */
	t_key_data									valid_sk;
	/** Index of first free CSK location */
	uint8_t										index_free_csk;
	/** Work buffer to store temporary key */
	/** Signing key identifier - it could be either SSK either CUK */
	struct __attribute__((packed))
	{
		/** Key identifier */
		e_km_keyid								id;
		/** Is key valid ? */
		uint8_t									valid;
		/** Slot where is stored the key */
		e_km_slob_nb							slot;
		/** Key descriptor */
		uint32_t								descriptor;
		/** Pointer on key */
		volatile uint8_t						*p_sign_key;
	} sign_key[N_KM_INDEX_COUNT];

} t_km_context;

/** Functions *****************************************************************/
int_pltfrm km_init(void *p_ctx, void *p_in, uint32_t length_in);
int_pltfrm km_shutdown(void *p_ctx);
int_pltfrm km_check_key(t_context *p_ctx, e_km_keyid key_id);
int_pltfrm km_check_key_slot(t_context *p_ctx, uint8_t slot, e_km_keyid key_id);
int_pltfrm km_check_csk(t_context *p_ctx);
int_pltfrm km_get_key(t_context *p_ctx, e_km_keyid key_id, t_km_key *p_key, uint32_t *p_key_size);
//int_pltfrm km_write_csk(uint8_t slot, t_key_data *p_cskdata);
int_pltfrm km_verify_signature(t_context *p_ctx,
								uint8_t *p_message,
								uint32_t mess_length,
								uint8_t *p_signature,
								e_km_support_algos algo,
								t_km_key key);
int_pltfrm km_verify_hash(t_context *p_ctx,
							uint8_t *p_message,
							uint32_t mess_length,
							uint8_t *p_hash);
/** Macros ********************************************************************/

#endif /* _KM_H_ */

/* End Of File */
