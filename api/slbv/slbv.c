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
 * @file slbv.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

/** Global includes */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <common.h>
#include <errors.h>
#include <patch.h>
#include <otp_mapping.h>
/** Other includes */
#include <api/scl_api.h>
#include <api/hardware/scl_hca.h>
#include <api/hash/sha.h>
#include <api/asymmetric/ecc/ecc.h>
#include <api/asymmetric/ecc/ecdsa.h>
#include <km.h>
#include <sbrm.h>
#include <slbv.h>
#include <slbv_internal.h>

/** External declarations */
extern uint32_t __iflash_start;
extern uint32_t __qspi_start;
extern uint32_t __qspi_size;
extern uint32_t	__sbr_free_start_addr;
extern uint32_t __sbr_free_end_addr;

/** Local declarations */
__attribute__((section(".bss"))) t_slbv_context slbv_context;

/******************************************************************************/
int_pltfrm slbv_init(void *p_ctx, void *p_in, uint32_t length_in)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;
		/** Initialize internal structure */
		memset((void*)&slbv_context, 0x00, sizeof(t_slbv_context));
		/** Then set structure parameters */
		slbv_context.decryption = FALSE;
		slbv_context.p_hdr = (volatile t_secure_header*)&__iflash_start;
		slbv_context.boot_addr = (volatile uintmax_t)&__iflash_start;
		/** Local context structure assignment */
		p_context->p_slbv_context = (volatile void*)&slbv_context;
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}


/******************************************************************************/
int_pltfrm slbv_shutdown(void *p_ctx)
{
	/** End Of Function */
	return NO_ERROR;
}

/******************************************************************************/
int_pltfrm slbv_process(t_context *p_ctx)
{
	int32_t										err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Verify application header and its signature */
		err = slbv_check_slb(p_ctx, N_SLBV_SLB_ID_E31);
		if( NO_ERROR == err )
		{
			/** Jump into SLB/SFL */
			slbv_context.jump_fct_ptr();
		}
	}
	/** Something goes wrong, let's reset the platform */
	sbrm_platform_reset(p_ctx);
	/** End Of Function */
	return err;
}

/******************************************************************************/
/** Look for Boot address */
int_pltfrm slbv_get_boot_address(t_context *p_ctx, uint_pltfrm *p_addr)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint_pltfrm									length = 128;

	/** Check input pointer */
	if( !p_ctx || !p_addr )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Initialize structure field */
		slbv_context.bootdev = 0;
		/** Retrieve parameter from OTP */
#ifdef _WITH_SCR_REGISTERS_
		slbv_context.bootdev = *((uint32_t*)C_REG_SCR_BASE_ADDRESS);
		err = NO_ERROR;
#else
		err = sbrm_read_otp(p_ctx, C_OTP_BOOTDEV_OFST, (uint8_t*)&slbv_context.bootdev, C_OTP_BOOTDEV_SIZE);
#endif /* _WITH_SCR_REGISTERS_ */
		if( NO_ERROR == err )
		{
			/** Check boot address depending on BOOTDEV parameter */
			if( C_OTP_BOOTDEV_QSPI_NOOFST == ( ( slbv_context.bootdev >> C_OTP_BOOTDEV_PATTERN_OFST ) & C_OTP_BOOTDEV_PATTERN_MASK_NOOFST ) )
			{
				/** Set base address for QSPI storage - 36bits */
				*(uint_pltfrm*)p_addr = (uint_pltfrm)&__qspi_start;
#ifdef _WITH_GPT_
				/** Initialize QSPI structure and parameters */
				slbv_context.boot.qspi = metal_qspi_get_device(C_SLBV_QSPI_PORT_ID);
				if( !slbv_context.boot.qspi )
				{
					/** Something goes wrong */
					err = N_SLBV_ERR_NO_INTERFACE_QSPI;
					goto slbv_get_boot_address_out;
				}
				/** Now initialize QSPI interface */
				metal_qspi_init(slbv_context.boot.qspi, C_SLBV_QSPI_BAUDRATE);
				/** QSPI is memory mapped, therefore it can be accessed directly with address */
#endif /* _WITH_GPT_ */
			}
			else
			{
				/** Error */
				err = N_SLBV_ERR_BOOTDEV_NOT_SUPPORTED;
				slbv_context.boot_addr = 0;
			}
		}
	}
slbv_get_boot_address_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm slbv_get_application_version(t_context *p_ctx, uint32_t *p_version)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	int32_t										slot = C_OTP_APP_REFV_SLOT_MAX;

	/** Check input pointer */
	if( !p_ctx || !p_version )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Look for non virgin slot */
		while( ( slot >= 0 ) && ( NO_ERROR != err ) )
		{
			/** Start from last slot */
			err = sbrm_read_otp(p_ctx, C_OTP_APP_REFV_AREA_OFST + ( slot * C_OTP_APP_REFV_ELMNT_SIZE ), (uint8_t*)p_version, C_OTP_APP_REFV_ELMNT_SIZE);
			if( (uint32_t)C_PATTERN_VIRGIN_32BITS != (uint32_t)*p_version )
			{
				/** Found */
				err = NO_ERROR;
			}
			else
			{
				/** Change 'err' */
				err = N_SLBV_ERR_NO_APP_REF_VERSION;
				/** Decrement slot number */
				slot--;
			}
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm slbv_check_slb(t_context *p_ctx, e_slbv_slb_id slb_id)
{
	uint8_t										loop = 0;
	uint8_t										i;
	/** By default FSBL is not considered as XiP */
	uint8_t										token_xip = FALSE;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	volatile uint_pltfrm						boundary_down = (uint_pltfrm)&__sbr_free_start_addr;
	volatile uint_pltfrm						boundary_up = (uint_pltfrm)&__sbr_free_end_addr;
	size_t										hash_len = 0;
	uint32_t									tmp = 0;
	uint32_t									rom_version = 0;
	uint32_t									raw_binary_size = 0;
	volatile uint32_t							tmp_size = 0;
	t_km_key									key;
	t_key_data									key_data;
	ecc_affine_point_t							Q;
	ecdsa_signature_t							signature;
	volatile uint8_t							*p_tmp;
	t_km_context								*p_km_ctx;
	volatile uint_pltfrm						addr_copy;
	volatile uint_pltfrm						addr_exec;
	/** Declare local pointer to stored formated binary */
	volatile uint_pltfrm						src_binary;
	e_km_keyid									key_sig;


	/** Check input pointer */
	if( !p_ctx || !p_ctx->p_km_context )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( N_SLBV_SLB_ID_E31 != slb_id )
	{
		/**  */
		err = N_SLBV_ERR_APPLI_TARGET_NOT_SUPPORTED;
	}
	else
	{
		/** Assign pointer */
		p_km_ctx = (t_km_context*)p_ctx->p_km_context;
		/** Retrieve where to search for FSBL */
		err = slbv_get_boot_address(p_ctx, (uint_pltfrm*)&slbv_context.boot_addr);
		if( err || !slbv_context.boot_addr )
		{
			/** Set default value - address of free area in internal RAM/Flash */
			slbv_context.boot_addr = (volatile uintmax_t)&__iflash_start;
		}
		/** Assign value then */
		slbv_context.p_hdr = (volatile t_secure_header*)slbv_context.boot_addr;
		/** Look for synchronization pattern **********************************/
		if( ( C_SFLV_MAGIC_WORD1 != slbv_context.p_hdr->magic_word1 ) ||
			( C_SFLV_MAGIC_WORD2 != slbv_context.p_hdr->magic_word2 ) )
		{
			/** Synchronization pattern(s), no match */
			err = N_SLBV_ERR_SYNC_PTRN_FAILURE;
			goto slbv_check_slb_out;
		}
		/** Check Secure Boot ROM version *************************************/
		rom_version = ( ( SBR_REF_VERSION_EDIT << C_SBR_REF_VERSION_EDIT_OFST ) & C_SBR_REF_VERSION_EDIT_MASK ) |\
						( ( SBR_REF_VERSION_MINOR << C_SBR_REF_VERSION_MINOR_OFST ) & C_SBR_REF_VERSION_MINOR_MASK ) |\
						( ( SBR_REF_VERSION_MAJOR << C_SBR_REF_VERSION_MAJOR_OFST ) & C_SBR_REF_VERSION_MAJOR_MASK );
		if( rom_version > slbv_context.p_hdr->rom_ref_version )
		{
			/** Application is not compatible */
			err = N_SLBV_ERR_HDR_VERSION_MISMATCH;
			goto slbv_check_slb_out;
		}
		/** Check firmware version given in header compare to the one from
		 * storage area (OTP) *************************************************/
		err = slbv_get_application_version(p_ctx, &slbv_context.ref_appli_version);
		if( N_SLBV_ERR_NO_APP_REF_VERSION == err )
		{
			/** Set very default version */
			slbv_context.ref_appli_version = (uint32_t)1UL;
		}
		else if( err )
		{
			/** Should not happen */
			goto slbv_check_slb_out;
		}
		/** Given version must be equal or greater than stored one */
		if( slbv_context.ref_appli_version > slbv_context.p_hdr->firmware_version )
		{
			/** Version does not match */
			err = N_SLBV_ERR_VERSION_MISMATCH;
			goto slbv_check_slb_out;
		}
		/** Check application type */
		switch( slbv_context.p_hdr->appli_type )
		{
			case N_SLBV_APP_TYPE_REGULAR:
				slbv_context.decryption = FALSE;
				break;
			case N_SLBV_APP_TYPE_ENCRYPTED:
			default:
				err = N_SLBV_ERR_APPLI_TYPE_NOT_SUPPORTED;
				goto slbv_check_slb_out;
		}
		/** Check address range ***********************************************/
		/** Now check binary size */
		if( ( ( sizeof(t_secure_header) + C_SIGNATURE_MAX_SIZE ) >= slbv_context.p_hdr->secure_appli_image_size ) &&
			( C_SEC_HDR_TWO_SIGNATURES == slbv_context.p_hdr->nb_signatures ) )
		{
			/** Size to small */
			err = N_SLBV_ERR_INVAL;
			goto slbv_check_slb_out;
		}
		else if( ( sizeof(t_secure_header) >= slbv_context.p_hdr->secure_appli_image_size ) &&
				( C_SEC_HDR_ONE_SIGNATURE == slbv_context.p_hdr->nb_signatures ) )
		{
			/** Size to small */
			err = N_SLBV_ERR_INVAL;
			goto slbv_check_slb_out;
		}
#ifdef _SLBV_OLD_BEHAVIOR_
		/** Check binary offset coherence */
		if( ( sizeof(t_secure_header) != slbv_context.p_hdr->fimware_start_offset ) &&
			( C_SEC_HDR_ONE_SIGNATURE == slbv_context.p_hdr->nb_signatures ) )
		{
			/** Offset does not match header size with 1 certificate */
			err = N_SLBV_ERR_INVAL_BINARY_OFST;
			goto slbv_check_slb_out;

		}
		else if( ( ( sizeof(t_secure_header) + C_SIGNATURE_MAX_SIZE ) != slbv_context.p_hdr->fimware_start_offset ) &&
				( C_SEC_HDR_TWO_SIGNATURES == slbv_context.p_hdr->nb_signatures ) )
		{
			/** Offset does not match header size with 2 certificates */
			err = N_SLBV_ERR_INVAL_BINARY_OFST;
			goto slbv_check_slb_out;
		}
#endif /** _SLBV_OLD_BEHAVIOR_ */
#if __riscv_xlen == 32
		/** 32bits */
		if( C_SEC_HDR_ADDRESS_SIZE_32BITS != slbv_context.p_hdr->address_size )
#elif __riscv_xlen == 64
		/** 64bits */
		if( C_SEC_HDR_ADDRESS_SIZE_64BITS != slbv_context.p_hdr->address_size )
#else
#error [__riscv_xlen] A value for bus width must be defined
#endif /* __riscv_xlen */
		{
			/**  */
			err = N_SLBV_ERR_ADDR_SIZE_NOT_SUPPORTED;
			goto slbv_check_slb_out;
		}
		/** Now */
		src_binary = (volatile uint_pltfrm)slbv_context.p_hdr;
		/** Then binary offset from header */
		src_binary += slbv_context.p_hdr->fimware_start_offset;
		/** Compute raw binary size : size given in header - binary offset*/
		raw_binary_size = slbv_context.p_hdr->secure_appli_image_size - ( sizeof(t_secure_header) + slbv_context.p_hdr->fimware_start_offset );
		if( C_SEC_HDR_TWO_SIGNATURES == slbv_context.p_hdr->nb_signatures )
		{
			raw_binary_size -= C_SIGNATURE_MAX_SIZE;
		}
		/** Check if raw binary size is coherent, i.e. it should be at least one instruction */
		if( ( p_ctx->misa & ( 0x1 << C_MISA_EXTENSION_BIT_COMPRESSED_OFST ) ) &&
			( sizeof(uint16_t) > raw_binary_size ) )
		{
			/** Binary is not even one compressed instruction */
			err = N_SLBV_ERR_BINARY_SIZE_INCOHERENCE;
			goto slbv_check_slb_out;
		}
		else if( !( p_ctx->misa & ( 0x1 << C_MISA_EXTENSION_BIT_COMPRESSED_OFST ) ) &&
				( sizeof(uint32_t) > raw_binary_size ) )
		{
			/** Binary is not even one compressed instruction */
			err = N_SLBV_ERR_BINARY_SIZE_INCOHERENCE;
			goto slbv_check_slb_out;
		}
		/** Verify that copy and execution addresses are consistent */
		/** Get copy address */
		memcpy((void*)&addr_copy, (const void*)slbv_context.p_hdr->copy_address, sizeof(uint_pltfrm));
		/** Get execution address */
		memcpy((void*)&addr_exec, (const void*)slbv_context.p_hdr->execution_address, sizeof(uint_pltfrm));
		/** Check if it's XiP */
#if __riscv_xlen == 32
		/** 32bits */
		if( C_PATTERN_VIRGIN_32BITS == addr_copy )
#elif __riscv_xlen == 64
		/** 64bits */
		if( C_PATTERN_VIRGIN_64BITS == addr_copy )
#else
#error [__riscv_xlen] A value for bus width must be defined
#endif /* __riscv_xlen */
		{
			/** Ok, it's eXecute in Place then updated boundaries */
			boundary_down = (uint_pltfrm)&__qspi_start;
			boundary_up = boundary_down + (uint_pltfrm)&__qspi_size;
			/** Update addr_copy to reflect XiP choice */
			addr_copy = boundary_down;
			/** Refresh token */
			token_xip = TRUE;
		}
		/** Check is copy address is in range if not XIP */
		else if( ( (uint_pltfrm)boundary_down <= addr_copy) && ( (uint_pltfrm)boundary_up >= ( addr_copy + raw_binary_size ) ) )
		{
			/** Ok, destination area is in range */
		}
		else
		{
			/** Copy address not in expected area */
			err = N_SLBV_ERR_NOT_IN_RANGE;
			goto slbv_check_slb_out;
		}
		/** Check if execution address is in destination area (copy address + binary size - 1 opcode size ) */
		if( ( addr_copy <= addr_exec ) &&
			( ( addr_copy + slbv_context.p_hdr->secure_appli_image_size - sizeof(uint32_t) ) >= addr_exec) )
		{
			/** Set 64bits execution address to context structure */
			slbv_context.jump_fct_ptr = addr_exec;
		}
		else
		{
			/** Execution address does not fit in */
			err = N_SLBV_ERR_EXEC_NOT_IN_RANGE;
			goto slbv_check_slb_out;
		}
		/** Certificate(s) management *****************************************/
		/** Check algorithm */
		if( N_KM_ALGO_ECDSA384 != slbv_context.p_hdr->algo )
		{
			/** Algorithm not supported */
			err = N_SLBV_ERR_ALGO_NOT_SUPPORTED;
			goto slbv_check_slb_out;
		}
		/** Set number of signatures to verify */
		if( C_SEC_HDR_ONE_SIGNATURE == slbv_context.p_hdr->nb_signatures )
		{
			/**  */
			loop = 1;
		}
#ifdef __WITH_2_SIGNATURES_SUPORT_
		else if ( C_SEC_HDR_TWO_SIGNATURES == slbv_context.p_hdr->nb_signatures )
		{
			/**  */
			loop = 2;
		}
#endif /* __WITH_2_SIGNATURES_SUPORT_ */
		else
		{
			/** Value is not in range */
			err = N_SLBV_ERR_NOT_SUPPORTED;
			goto slbv_check_slb_out;
		}
		/** Check key(s) coherence */
		if( ( C_SEC_HDR_ONE_SIGNATURE == slbv_context.p_hdr->nb_signatures ) &&
				( N_KM_KEYID_CSK != slbv_context.p_hdr->sign_keyid_1 ) )
		{
			/**  */
			err = N_SLBV_ERR_KEY_INCOHERENCE;
			goto slbv_check_slb_out;
		}
		else if( C_EDCSA384_SIZE_BITS != slbv_context.p_hdr->signature_size_bits )
		{
			/** Bad key size */
			err = N_SLBV_ERR_WRONG_KEY_SIZE;
			goto slbv_check_slb_out;
		}
		/** Check signature(s) - Enter the loop */
		for( i = 0;i < loop;i++ )
		{
			/** Initialize key buffer */
			memset((void*)&key_data, 0x00, sizeof(t_key_data));
			/** Assign pointers */
			key.p_descriptor = (uint32_t*)&key_data.algo;
			key.ecdsa.p_x = (uint8_t*)key_data.key;
			key.ecdsa.p_y = key.ecdsa.p_x + C_EDCSA384_SIZE;
			key.certificate.p_x = (uint8_t*)key_data.certificate;
			key.certificate.p_y = key.certificate.p_x + C_EDCSA384_SIZE;
			switch( i )
			{
				case 0:
					key_sig = slbv_context.p_hdr->sign_keyid_1;
					break;
				case 1:
					key_sig = slbv_context.p_hdr->sign_keyid_2;
					break;
				default:
					err = GENERIC_ERR_CRITICAL;
					goto slbv_check_slb_out;
			}
			/** Retrieve key */
			err = km_get_key(p_ctx,
								key_sig,
								(t_km_key*)&key,
								(uint32_t*)&tmp);
			if( err )
			{
				/** Valid CSK not available/found */
				err = N_SLBV_ERR_NO_CSK_AVIALABLE;
				goto slbv_check_slb_out;
			}
			/**  */
			/** Initialization of hash buffer */
			err = scl_sha_init((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
								SCL_HASH_SHA384);
			if( SCL_OK != err )
			{
				/** Critical error */
				err = N_SLBV_ERR_CRYPTO_FAILURE;
				goto slbv_check_slb_out;
			}
			/** Hash header without signature */
			p_tmp = (volatile uint8_t*)slbv_context.p_hdr;
			/** Remove signature from structure size */
			tmp_size = (volatile uint32_t)sizeof(t_secure_header) - C_SIGNATURE_MAX_SIZE;
			err = scl_sha_core((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
								p_tmp,
								tmp_size);
			if( SCL_OK != err )
			{
				/** Should not happen */
				err = GENERIC_ERR_CRITICAL;
				goto slbv_check_slb_out;
			}

			/** Hash binary image, starting from just after signature */
			p_tmp = (volatile uint8_t*)slbv_context.p_hdr + sizeof(t_secure_header);
			/**  */
			tmp_size = (volatile uint32_t)slbv_context.p_hdr->secure_appli_image_size - sizeof(t_secure_header);
			/** If 2 signatures then remove one ECDSA384 signature size */
			if( C_SEC_HDR_TWO_SIGNATURES == slbv_context.p_hdr->nb_signatures )
			{
				tmp_size -= C_SIGNATURE_MAX_SIZE;
			}
			/** Hash binary image */
			err = scl_sha_core((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
								p_tmp,
								tmp_size);
			if( SCL_OK != err )
			{
				/** Should not happen */
				err = GENERIC_ERR_CRITICAL;
				goto slbv_check_slb_out;
			}
			/** Then finish computation */
			hash_len = sizeof(p_ctx->digest);
			memset((void*)p_ctx->digest, 0x00, SHA384_BYTE_HASHSIZE);
			err = scl_sha_finish((metal_scl_t*)p_ctx->p_metal_sifive_scl,
									(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
									p_ctx->digest,
									&hash_len);
			if( SCL_OK != err )
			{
				/** Critical error */
				err = GENERIC_ERR_CRITICAL;
				goto slbv_check_slb_out;
			}
			/** Assign parameters */
			Q.x = key.ecdsa.p_x;
			Q.y = key.ecdsa.p_y;
			signature.r = (uint8_t*)( slbv_context.p_hdr->signature + ( i * C_SIGNATURE_MAX_SIZE ) );
			signature.s = signature.r + C_EDCSA384_SIZE;
			/** Check certificate */
			err = scl_ecdsa_verification((metal_scl_t*)p_ctx->p_metal_sifive_scl,
											&ecc_secp384r1,
											(const ecc_affine_const_point_t *const)&Q,
											(const ecdsa_signature_const_t *const)&signature,
											p_ctx->digest,
											SHA384_BYTE_HASHSIZE);
			if( SCL_OK != err )
			{
				/** SLB is not granted to be executed on this platform */
				err = N_SLBV_ERR_CRYPTO_FAILURE;
				goto slbv_check_slb_out;
			}
			else
			{
				/** No error */
				err = NO_ERROR;
			}
		}
		/** Check if FSBL is XIP or not, if so install it */
		if( FALSE == token_xip )
		{
			/** If not, SLB has been checked ok, let's copy it at destination area */
			memcpy((void*)addr_copy,
					(const void*)( slbv_context.p_hdr + slbv_context.p_hdr->fimware_start_offset ),
					raw_binary_size);
		}
	}
slbv_check_slb_out:
	/** End Of Function */
	return err;
}


/******************************************************************************/
/* End Of file */
