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
 * @file example-secure-bootroom.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

/** Global includes */
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <common.h>
#include <errors.h>
#include <patch.h>
#ifdef _WITH_GPIO_CHARAC_
#include <metal/led.h>
#endif /* _WITH_GPIO_CHARAC_ */
/** Other includes */
#include <api/scl_api.h>
#if defined(HCA_HAS_SHA)
#include <api/hardware/scl_hca.h>
#else
#include <api/software/scl_soft.h>
#endif /* HCA_HAS_SHA */
#include <api/software/bignumbers/soft_bignumbers.h>
#include <api/software/asymmetric/ecc/soft_ecc.h>
#include <api/software/asymmetric/ecc/soft_ecdsa.h>
#include <api/hash/sha.h>
#include <km.h>
#include <pi.h>
#include <ppm.h>
#include <sp.h>
#include <sp_internal.h>
#include <slbv.h>
#include <otp_mapping.h>
#include <sbrm_internal.h>
#include <sbrm.h>
/** Local includes */


/** External declarations */
/** Local declarations */
__attribute__((section(".bss"),aligned(0x10))) scl_sha_ctx_t hash_ctx;
__attribute__((section(".bss"))) volatile t_context context;
/** SCL context structure */
#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0,5,0)
metal_scl_t metal_sifive_scl = {
    .aes_func = {
        .setkey = default_aes_setkey,
        .setiv  = default_aes_setiv,
        .cipher = default_aes_cipher,
        .auth_init = default_aes_auth_init,
        .auth_core = default_aes_auth_core,
        .auth_finish = default_aes_auth_finish
    },
#if defined(HCA_HAS_SHA)
    .hash_func = {
        .sha_init = hca_sha_init,
        .sha_core = hca_sha_core,
        .sha_finish = hca_sha_finish
    },
# else
    .hash_func = {
        .sha_init = soft_sha_init,
        .sha_core = soft_sha_core,
        .sha_finish = soft_sha_finish
    },
# endif /* HCA_HAS_SHA */
    .trng_func = {
        .init = default_trng_init,
        .get_data = default_trng_getdata
    },
   .bignum_func =
		{
			.compare = soft_bignum_compare,
			.compare_len_diff = soft_bignum_compare_len_diff,
			.is_null = soft_bignum_is_null,
			.negate = soft_bignum_negate,
			.inc = soft_bignum_inc,
			.add = soft_bignum_add,
			.sub = soft_bignum_sub,
			.mult = soft_bignum_mult,
			.square = soft_bignum_square_with_mult,
			.leftshift = soft_bignum_leftshift,
			.rightshift = soft_bignum_rightshift,
			.msb_set_in_word = soft_bignum_msb_set_in_word,
			.get_msb_set = soft_bignum_get_msb_set,
			.set_bit = soft_bignum_set_bit,
			.div = soft_bignum_div,
			.mod = soft_ecc_mod,
			.set_modulus = soft_bignum_set_modulus,
			.mod_add = soft_bignum_mod_add,
			.mod_sub = soft_bignum_mod_sub,
			.mod_mult = soft_bignum_mod_mult,
			.mod_inv = soft_bignum_mod_inv,
			.mod_square = soft_bignum_mod_square,
		},
	.ecdsa_func =
		{
			.signature = NULL,
			.verification = soft_ecdsa_verification,
		},
    .hca_base = METAL_SIFIVE_HCA_0_BASE_ADDRESS
};
#else
metal_scl_t metal_sifive_scl = {
    .aes_func = {
        .setkey = default_aes_setkey,
        .setiv  = default_aes_setiv,
        .cipher = default_aes_cipher,
        .auth_init = default_aes_auth_init,
        .auth_core = default_aes_auth_core,
        .auth_finish = default_aes_auth_finish
    },
    .hash_func = {
        .sha_init = soft_sha_init,
        .sha_core = soft_sha_core,
        .sha_finish = soft_sha_finish
    },
    .trng_func = {
        .init = default_trng_init,
        .get_data = default_trng_getdata
    },
   .bignum_func =
	{
		.compare = soft_bignum_compare,
		.compare_len_diff = soft_bignum_compare_len_diff,
		.is_null = soft_bignum_is_null,
		.negate = soft_bignum_negate,
		.inc = soft_bignum_inc,
		.add = soft_bignum_add,
		.sub = soft_bignum_sub,
		.mult = soft_bignum_mult,
		.square = soft_bignum_square_with_mult,
		.leftshift = soft_bignum_leftshift,
		.rightshift = soft_bignum_rightshift,
		.msb_set_in_word = soft_bignum_msb_set_in_word,
		.get_msb_set = soft_bignum_get_msb_set,
		.set_bit = soft_bignum_set_bit,
		.div = soft_bignum_div,
		.mod = soft_ecc_mod,
		.set_modulus = soft_bignum_set_modulus,
		.mod_add = soft_bignum_mod_add,
		.mod_sub = soft_bignum_mod_sub,
		.mod_mult = soft_bignum_mod_mult,
		.mod_inv = soft_bignum_mod_inv,
		.mod_square = soft_bignum_mod_square,
	},
	.ecdsa_func =
	{
		.signature = NULL,
		.verification = soft_ecdsa_verification,
	},
    .hca_base = 0
};
#endif /* METAL_SIFIVE_HCA_VERSION */

/******************************************************************************/
int_pltfrm context_initialization(t_context *p_ctx)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
#ifdef _WITH_GPIO_CHARAC_
	uint8_t										i;
#endif /* _WITH_GPIO_CHARAC_ */

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Get Machine ISA information */
		__asm__ volatile("csrr %0, misa" : "=r"(p_ctx->misa));
		/** Assigning function pointers tables */
		p_ctx->p_metal_sifive_scl = (volatile metal_scl_t*)&metal_sifive_scl;
		/** Assignment for data pointers */
		p_ctx->p_scl_hash_ctx = (volatile scl_sha_ctx_t*)&hash_ctx;
		/** No error */
		err = NO_ERROR;
#ifdef _WITH_GPIO_CHARAC_
		/** Register GPIO0 */
		p_ctx->gpio0 = (struct metal_gpio *)&__metal_dt_gpio_20002000;
		/** Configure pin as output */
		for(i = C_GPIO0_OFFSET;i < ( C_GPIO0_OFFSET + C_GPIO0_NB );i++ )
		{
			metal_gpio_disable_input(p_ctx->gpio0, i);
			metal_gpio_enable_output(p_ctx->gpio0, i);
		}
		/** Retrieve LEDs RGB */
		/** Red */
	    p_ctx->led[0] = metal_led_get_rgb("LD0", "red");
	    /** Green */
	    p_ctx->led[1] = metal_led_get_rgb("LD0", "green");
	    /** Blue */
	    p_ctx->led[2] = metal_led_get_rgb("LD0", "blue");
	    /** Check result */
	    if( !p_ctx->led[0] || !p_ctx->led[1] || !p_ctx->led[2] )
	    {
	        err = GENERIC_ERR_NULL_PTR;
	        goto context_initialization_out;
	    }
	    /** Enable each LED */
	    metal_led_enable(p_ctx->led[0]);
	    metal_led_enable(p_ctx->led[1]);
	    metal_led_enable(p_ctx->led[2]);
	    /** All Off */
	    metal_led_off(p_ctx->led[0]);
	    metal_led_off(p_ctx->led[1]);
	    metal_led_off(p_ctx->led[2]);
#endif /*  */
	}
#ifdef _WITH_GPIO_CHARAC_
context_initialization_out:
#endif /* _WITH_GPIO_CHARAC_ */
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm main(void)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

#ifdef _FPGA_SPECIFIC_
	/** Specific procedures and workarounds for FPGA platform */

	/** Program parameters in OTP - emulated in iRAM */

	/** OTP arrays are in .data section, therefore installed directly at platform initialization */
#endif /** _FPGA_SPECIFIC_ */
	/** Check SBR CRC */
	err = sbrm_check_rom_crc();
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** By default, L2 is set as scratchpad */
	/**  */
	err = context_initialization((t_context*)&context);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize SBRM module */
	err = sbrm_init((void*)&context, NULL, 0);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize PPM Module */
	err = ppm_init((void*)&context, NULL, 0);
	if( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize SP module */
	err = sp_init((void*)&context, NULL, 0);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize KM module */
	err = km_init((void*)&context, NULL, 0);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Initialize SLBV module */
	err = slbv_init((void*)&context, NULL, 0);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Perform self-tests */
	err = sbrm_selftest((t_context*)&context);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Go to shutdown mode */
		sbrm_shutdown((t_context*)&context);
		/** It should not go by here */
		goto main_out;
	}
	/** Retrieve platform life cycle */
	err = ppm_get_life_cycle((t_context*)&context);
	if ( err )
	{
		/** Return value is not null thus error */
		/** But Life Cycle Pattern should have been set to Phase#U */
	}
	/** Treat platform life cycle */
	err = ppm_manage_life_cycle((t_context*)&context);
	if ( err )
	{
		/** Return value is not null thus error */
		/** Depending on return value, perform specific action */
	}
	/** It should not go by here */
	while( 1 );
main_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
/* End Of File */
