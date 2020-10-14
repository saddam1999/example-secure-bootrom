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
 * @file km.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

/** Global includes */
#include <stdio.h>
#include <string.h>
/** Other includes */
#include <errors.h>
#include <common.h>
#include <otp_mapping.h>
#include <patch.h>
#include <api/scl_api.h>
#include <api/hardware/scl_hca.h>
#include <api/hash/sha.h>
#include <api/asymmetric/ecc/ecc.h>
#include <api/asymmetric/ecc/ecdsa.h>
#include <scl/scl_init.h>
#include <scl/scl_ecdsa.h>
#include <sbrm.h>
/** Local includes */
#include <km.h>
#include <km_internal.h>

/** External declarations */
extern uint8_t ssk_descriptor[];
extern uint8_t ssk[2 * C_EDCSA384_SIZE];
/** Local declarations */
/** SCL work buffer - size 8 kBytes / 2k (32bits) Words */
__attribute__((section(".bss"))) t_km_context km_context;



/******************************************************************************/
int_pltfrm km_init(void *p_ctx, void *p_in, uint32_t length_in)
{
	uint8_t										i;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Null pointer */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;
		/** Assign pointer on local context structure */
		p_context->p_km_context = (volatile void*)&km_context;
		/** Initialize context structure */
		memset((void*)&km_context, 0x00, sizeof(t_km_context));
		/** Fill out parameters */
		for( i = N_KM_INDEX_MIN;i <= N_KM_INDEX_MAX;i++ )
		{
			/** Set no valid slot for all the keys. I'll be updated later */
			km_context.sign_key[i].slot = K_KM_SLOT_NOT_SET;
		}
		/** For initialization, default value is invalid value - 0xff */
		km_context.index_free_csk = C_PATTERN_VIRGIN_8BITS;
		/** For initialization, default signing key is SSK */
		km_context.sign_key[N_KM_INDEX_PSK].id = N_KM_KEYID_SSK;
		/** Initializing SCL work buffer */
		err = scl_init((metal_scl_t*)p_context->p_metal_sifive_scl);
		if( SCL_OK != err )
		{
			/** Error initializing SCL library */
			err = N_KM_ERR_SCL_INITIALIZATION_FAILURE;
		}
		else
		{
			/**  */
			if( !p_context->p_scl_hash_ctx )
			{
				/** Pointer should not be null */
				err = GENERIC_ERR_NULL_PTR;
				goto km_init_out;
			}
			/** Then initialize hash context */
			/** Initialize cryptographic library context for hash computation */
#ifdef _WITH_GPIO_CHARAC_
			/** Red LED Off/On */
			metal_led_off(p_context->led[0]);
			metal_led_on(p_context->led[0]);
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_context->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err = scl_sha_init((metal_scl_t*)p_context->p_metal_sifive_scl,
								(scl_sha_ctx_t*)p_context->p_scl_hash_ctx,
								SCL_HASH_SHA384);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_context->gpio0, C_GPIO0_SHA, 0);
			/** Red LED Off */
			metal_led_off(p_context->led[0]);
#endif /* _WITH_GPIO_CHARAC_ */
			if ( SCL_OK != err )
			{
				/** Error in cryptographic initialization */
				err = N_KM_ERR_SCL_INITIALIZATION_FAILURE;
			}
			else
			{
				/** No error; */
				err = NO_ERROR;
			}
		}
	}
km_init_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm km_shutdown(void *p_ctx)
{
	/** End Of Function */
	return NO_ERROR;
}

/******************************************************************************/
/** Note that function is really not optimized
 * Purpose, for first draft, is to have working function */
int_pltfrm km_check_key(t_context *p_ctx, e_km_keyid key_id)
{
	uint8_t										loop = N_KM_INDEX_COUNT;
	uint32_t									key_size = 0;
	uint32_t									i;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint_pltfrm									offset_desc = 0;
	e_km_key_index								key_index;
	e_km_keyid									key_ref_id;
	t_key_data									key_data;
	t_km_key									key;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** First check the descriptor */
		switch( key_id )
		{
			case N_KM_KEYID_SSK:
				/** Nothing to verify */
				err = NO_ERROR;
				goto km_check_key_out;
			case N_KM_KEYID_CSK:
				/** Set index */
				key_index = N_KM_INDEX_CSK;
				/** Check if valid CSK has been registered */
				if( K_KM_SLOT_MAX < km_context.sign_key[key_index].slot )
				{
					/** No CSK has been programmed yet */
					loop = K_KM_SLOT_MAX;
				}
				else
				{
					/** Let's start with last valid one then */
					loop = km_context.sign_key[key_index].slot;
				}
				/** Reference key */
				key_ref_id = N_KM_KEYID_SSK;
				break;
			default:
				goto km_check_key_out;
		}
		/** Search for valid key in among key's slot(s) */
		for( i = ( loop + 1 );i > 0;i-- )
		{
			/** Only for CSK */
			if( N_KM_KEYID_CSK == key_id )
			{
				/** Compute offset where is stored current CSK */
				offset_desc = C_OTP_CSK0_DESC_OFST + ( C_OTP_CSK_AERA_SIZE * ( i - 1 ) );
			}
			/** Check if slot is free */
			err = km_check_key_slot(p_ctx, ( i - 1 ), key_id);
			if( N_KM_ERR_NOT_VIRGIN == err )
			{
				/** Something is present */
			}
			else if( NO_ERROR == err )
			{
				/** No key is present */
				if( N_KM_KEYID_CSK != key_id )
				{
					/** That's a problem */
					err = N_KM_ERR_NO_KEY;
					goto km_check_key_out;
				}
				else
				{
					/** CSK then let's move on */
					km_context.index_free_csk = ( i - 1 );
					continue;
				}
			}
			else
			{
				/** Should not happen */
				err = GENERIC_ERR_CRITICAL;
			}
			/** The length to read may be too large for CUK and CSK because security certificate
			 * is no ECDSA383 signature but SHA384 hash */
			key.p_descriptor = (uint32_t*)&key_data.algo;
			key.ecdsa.p_x = (uint8_t*)key_data.key;
			key.ecdsa.p_y = (uint8_t*)( key_data.key + C_EDCSA384_SIZE );
			key.certificate.p_x = (uint8_t*)key_data.certificate;
			key.certificate.p_y = (uint8_t*)( key_data.certificate + C_EDCSA384_SIZE );
			/** Here, key is retrieved at the same time as its descriptor and certificate */
			err = sbrm_read_otp(p_ctx, offset_desc, (uint8_t*)&key_data.algo, sizeof(t_key_data));
			if( err )
			{
				/** Should not happen */
				goto km_check_key_out;
			}
			/** Check stored values */
			if( ( N_KM_ALGO_ECDSA384 != key_data.algo ) ||
				( ( C_EDCSA384_SIZE * 8 ) != key_data.key_size_bits ) )
			{
				/** No valid key */
				err = N_KM_ERR_INVALID_KEY;
				/** Keep information that key is invalid */
				km_context.sign_key[key_index].valid = FALSE;
				continue;
			}
			/** Check if reference key stored is the good one */
			else if( key_data.sign_key_id != key_ref_id )
			{
				/** Reference key stored and expected one are not identical */
				err = N_KM_ERR_WRONG_REF_KEY;
				continue;
			}
			else
			{
				/** Descriptor parameters look ok, then use chosen key */
				km_context.sign_key[key_index].id = key_id;
			}
			/** Let's verify the key certificate */
			/** Hash (SHA384) verification */
			err = km_verify_hash(p_ctx,
									(uint8_t*)&key_data,
									(uint32_t)( sizeof(t_key_data) - sizeof(key_data.certificate) ),
									(uint8_t*)key_data.certificate);
			if( N_KM_ERR_INVALID_HASH == err )
			{
				/** Security problem */
				km_context.sign_key[key_id].valid = FALSE;
				continue;
			}
			else if( err )
			{
				/** Non security problem */
				continue;
			}
			/** Key has been checked ok then */
			km_context.sign_key[key_index].valid = TRUE;
			km_context.sign_key[key_index].slot = ( i - 1 );
			/** Update signing key storage */
			memcpy((void*)&km_context.valid_sk, (const void*)&key_data, sizeof(t_key_data));
		}
	}
km_check_key_out:
	/** Zero-ize buffer */
	memset((void*)&key_data, 0x00, sizeof(t_key_data));
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm km_check_key_slot(t_context *p_ctx, uint8_t slot, e_km_keyid key_id)
{
	register uint32_t							i;
	uint32_t									length;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint_pltfrm									offset;
	t_key_data									csk_area;
	uint32_t									*p_key_area = (uint32_t*)&csk_area;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer must not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto km_check_key_slot_out;
	}
	else
	{
		/** Check key identifier */
		switch( key_id )
		{
			case N_KM_KEYID_CSK:
				/** Set parameters */
				offset = C_OTP_CSK_AREA_OFST;
				length = C_OTP_CSK_AERA_SIZE;
				if( C_OTP_CSK_SLOT_MAX < slot )
				{
					/**  */
					err = N_KM_ERR_WRONG_SLOT;
					goto km_check_key_slot_out;
				}
				break;
			default:
				goto km_check_key_slot_out;
		}
		/** Point on requested CSK slot */
		err = sbrm_read_otp(p_ctx,
							( offset + ( slot * length ) ),
							(uint8_t*)p_key_area,
							length);
		if( err )
		{
			/** Should not happen */
			goto km_check_key_slot_out;
		}
		/** Set return value if area is virgin */
		err = NO_ERROR;
		/** Check area */
		for( i = 0;i < ( length / sizeof(uint32_t) );i++ )
		{
			/** Check virgin pattern */
			if ( C_PATTERN_VIRGIN_32BITS != p_key_area[i] )
			{
				/** Not virgin */
				err = N_KM_ERR_NOT_VIRGIN;
				break;
			}
		}
	}
km_check_key_slot_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm km_get_key(t_context *p_ctx, e_km_keyid key_id, t_km_key *p_key, uint32_t *p_key_size)
{
	uint32_t									size_key = 0;
	uint32_t									size_cert = 0;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint_pltfrm									offset_desc = 0;
	uint_pltfrm									offset_key = 0;
	uint_pltfrm									offset_cert = 0;
	uint8_t										*p_tmp = (uint8_t*)p_key;

	/** Check input parameters - case '*p_key' null is not relevant */
	if( !p_key || !p_key_size || !p_ctx ||  !p_key->p_descriptor )
	{
		/** At least, one pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Choose key */
		switch( key_id )
		{
			case N_KM_KEYID_SSK:
				/** Descriptor */
				p_key->p_descriptor = (uint32_t*)ssk_descriptor;
				/** Assign already existing array */
				p_key->ecdsa.p_x = (uint8_t*)ssk;
				p_key->ecdsa.p_y = (uint8_t*)( p_key->ecdsa.p_x + C_EDCSA384_SIZE );
				/** Set key size */
				*p_key_size = (uint32_t)sizeof(ssk);
				/** No error */
				err = NO_ERROR;
				goto km_get_key_out;
			case N_KM_KEYID_CSK:
				/** Check if valid CSK has been registered */
				if( K_KM_SLOT_MAX < km_context.sign_key[N_KM_INDEX_CSK].slot )
				{
					/** No CSK has been programmed yet */
					err = N_KM_ERR_NO_CSK;
					goto km_get_key_out;
				}
				else if( FALSE == km_context.sign_key[N_KM_INDEX_CSK].valid )
				{
					/** No CSK valid */
					err = N_KM_ERR_CSK_INVALID;
					goto km_get_key_out;
				}
				/** Compute offset were is stored current CSK */
				offset_desc = C_OTP_CSK0_DESC_OFST + ( C_OTP_CSK_AERA_SIZE * km_context.sign_key[N_KM_INDEX_CSK].slot );
				offset_key = offset_desc + C_OTP_CSK_DESC_ELMT_SIZE;
				offset_cert = offset_key + C_OTP_CSK_KEY_SIZE;
				size_key = C_OTP_CSK_KEY_SIZE;
				size_cert = C_OTP_CSK_CERT_SIZE;
				break;
			default:
				err = N_KM_ERR_NO_KEY;
				goto km_get_key_out;
		}
		/** Read data from storage area, descriptor first */
		err = sbrm_read_otp(p_ctx, offset_desc, (uint8_t*)p_key->p_descriptor, C_OTP_KEY_DESC_SIZE);
		if( err )
		{
			/** Storage read failed */
			goto km_get_key_out;
		}
		/** ... then the key ... */
		err = sbrm_read_otp(p_ctx, offset_key, (uint8_t*)p_key->ecdsa.p_x, size_key);
		if( err )
		{
			/** Storage read failed */
			goto km_get_key_out;
		}
		/** ... and now its certificate */
		err = sbrm_read_otp(p_ctx, offset_cert, (uint8_t*)p_key->certificate.p_x, size_cert);
		if( err )
		{
			/** Storage read failed */
			goto km_get_key_out;
		}
		/**  */
		*p_key_size = (uint32_t)sizeof(t_km_key);
		/** Return value is then directly passed */
	}
km_get_key_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm km_verify_signature(t_context *p_ctx,
								uint8_t *p_message,
								uint32_t mess_length,
								uint8_t *p_signature,
								e_km_support_algos algo,
								t_km_key key)
{
	uint8_t										loop;
	int_pltfrm 									err[C_KM_VERIFY_LOOP_MAX];
	size_t										hash_len = 0;
	ecc_affine_point_t							Q;
	ecdsa_signature_t							signature;


	/** Initialize error array */
	for( loop = 0;loop < C_KM_VERIFY_LOOP_MAX;loop++ )
	{
		err[loop] = GENERIC_ERR_UNKNOWN;
	}
	/** Check input pointers */
	if( !p_message || !p_signature || !p_ctx )
	{
		/** At least one of the pointers is null */
		err[0] = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Check algorithm */
		switch( algo )
		{
#ifdef _SUPPORT_ALGO_RSA2048_
		case N_KM_ALGO_RSA2048:
			break;
#endif /* _SUPPORT_ALGO_RSA2048_ */
#ifdef _SUPPORT_ALGO_RSA4096_
		case N_KM_ALGO_RSA4096:
			break;
#endif /* _SUPPORT_ALGO_RSA4096_ */
#ifdef _SUPPORT_ALGO_ECDSA256_
		case N_KM_ALGO_ECDSA256:
			break;
#endif /* _SUPPORT_ALGO_ECDSA256_ */
#ifdef _SUPPORT_ALGO_ECDSA384_
		case N_KM_ALGO_ECDSA384:
			break;
#endif /* _SUPPORT_ALGO_ECDSA384_ */
		default:
			err[0] = N_KM_ERR_ALGO_NOT_SUPPORTED;
			goto km_verify_signature_out;
		}
		/** Algorithm is supported then call cryptographic library */
		for( loop = 0;loop < C_KM_VERIFY_LOOP_MAX;loop++ )
		{
			/** Free digest */
			memset((void*)p_ctx->digest, 0x00, sizeof(p_ctx->digest));
			/** First compute hash */
			hash_len = sizeof(p_ctx->digest);
#ifdef _WITH_GPIO_CHARAC_
			/** Red LED Off/On */
			metal_led_off(p_ctx->led[0]);
			metal_led_on(p_ctx->led[0]);
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err[loop] = scl_sha((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								SCL_HASH_SHA384,
								p_message,
								mess_length,
								p_ctx->digest,
								&hash_len);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
#endif /* _WITH_GPIO_CHARAC_ */
			/** Set parameters */
			Q.x = key.ecdsa.p_x;
			Q.y = key.ecdsa.p_y;
			signature.r = p_signature;
			signature.s = p_signature + C_EDCSA384_SIZE;
			hash_len = sizeof(p_ctx->digest);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO check ECDSA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA_ECDSA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err[loop] = scl_ecdsa_verification((metal_scl_t*)p_ctx->p_metal_sifive_scl,
												&ecc_secp384r1,
												(const ecc_affine_const_point_t *const)&Q,
												(const ecdsa_signature_const_t *const)&signature,
												p_ctx->digest,
												hash_len);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO check ECDSA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA_ECDSA, 0);
			/** Red LED Off */
			metal_led_off(p_ctx->led[0]);
#endif /* _WITH_GPIO_CHARAC_ */
		}
	}
	/** If one of the returned value is not Ok then error */
	for( loop = 0;loop < C_KM_VERIFY_LOOP_MAX;loop++ )
	{
		if ( SCL_OK != err[loop] )
		{
			/** Set error value to default index */
			err[0] = N_KM_ERR_INVALID_SIGNATURE;
			break;
		}
	}
km_verify_signature_out:
	/** End Of Function */
	return err[0];
}

/******************************************************************************/
int_pltfrm km_verify_hash(t_context *p_ctx,
							uint8_t *p_message,
							uint32_t mess_length,
							uint8_t *p_hash)
{
	uint8_t										loop;
	size_t										hash_len = 0;
	int_pltfrm 									err[C_KM_VERIFY_LOOP_MAX];
	uint8_t										hash[C_EDCSA384_SIZE];

	/** Check input parameter */
	if( !p_message || !p_hash || !p_ctx )
	{
		/** Input pointer is null */
		err[0] = GENERIC_ERR_NULL_PTR;
	}
	else if( !mess_length )
	{
		/** Nothing to hash then */
		err[0] = GENERIC_ERR_INVAL;
	}
	/** Let's compute the hash */
	else
	{
		for( loop = 0;loop < C_KM_VERIFY_LOOP_MAX;loop++ )
		{
			/** Call to SiFive Cryptographic Library */
			hash_len = sizeof(hash);
#ifdef _WITH_GPIO_CHARAC_
			/** Red LED Off/On */
			metal_led_off(p_ctx->led[0]);
			metal_led_on(p_ctx->led[0]);
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err[loop] = scl_sha((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								SCL_HASH_SHA384,
								p_message,
								mess_length,
								hash,
								&hash_len);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
			/** Red LED Off */
			metal_led_off(p_ctx->led[0]);
#endif /* _WITH_GPIO_CHARAC_ */
			/** If one of the returned value is not Ok then error */
			if ( SCL_OK != err[loop] )
			{
				/** Set error value to default index */
				err[0] = N_KM_ERR_SCL_PROBLEM;
				goto km_verify_hash_out;
			}
			/** Now compare hash */
			err[loop] = memcmp((const void*)p_hash, (const void*)hash, sizeof(hash));
		}
		/** Computation has been done twiceCheck results then */
		/** If one of the returned value is not Ok then error */
		for( loop = 0;loop < C_KM_VERIFY_LOOP_MAX;loop++ )
		{
			if ( err[loop] )
			{
				/** Set error value to default index */
				err[0] = N_KM_ERR_INVALID_HASH;
				goto km_verify_hash_out;
			}
		}
		/** No error, useless code but who knows ... */
		err[0] = NO_ERROR;
	}
km_verify_hash_out:
	/** End Of Function */
	return err[0];
}

/******************************************************************************/
/* End Of File */
