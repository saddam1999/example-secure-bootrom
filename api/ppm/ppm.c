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
 * @file ppm.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


/** Global includes */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errors.h>
#include <otp_mapping.h>
/** Other includes */
#include <km.h>
#include <pi.h>
#include <ppm.h>
#include <sp.h>
#include <slbv.h>
#include <sbrm.h>
/** Local includes */
#include <ppm.h>
#include <ppm_internal.h>

/** External declarations */
/** Local declarations */
__attribute__((section(".bss"))) volatile t_ppm_context ppm_context;


/******************************************************************************/
int_pltfrm ppm_init(void *p_ctx, void *p_in, uint32_t length_in)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input parameter */
	if ( !p_ctx )
	{
		/** Input pointer is null, not good */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;
		/** Initialize context structure */
		memset((void*)&ppm_context, 0x00, sizeof(t_ppm_context));
		/** Always initialize life cycle pattern to "unknown" */
		ppm_context.lifecycle_phase = N_PPM_PHASE_U;
		/** Assign context structure pointer */
		p_context->p_ppm_context = (volatile void*)&ppm_context;
		/** No error */
		err = NO_ERROR;
	}
	/** End of function */
	return err;
}

/******************************************************************************/
int_pltfrm ppm_shutdown(void *p_ctx)
{
	/** End Of Function */
	return NO_ERROR;
}


/******************************************************************************/
int_pltfrm ppm_get_life_cycle(t_context *p_ctx)
{
	uint32_t									lcp = 0;
	int_pltfrm 									err = GENERIC_ERR_NULL_PTR;

	if( !p_ctx )
	{
		/** Pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Read OTP */
		err = sbrm_read_otp(p_ctx, C_OTP_LCP_OFST, (uint8_t*)&lcp, C_OTP_LCP_SIZE);
		if( err )
		{
			/** Set platform to Phase#U */
			ppm_context.lifecycle_phase = N_PPM_PHASE_U;
			err = N_PPM_ERR_CANT_RETRIEVE_LCP;
		}
		else if( C_OTP_LCP_1_PATTERN == ( lcp & C_OTP_LCP_1_MASK ) )
		{
			/** Initialize platform phase value */
			ppm_context.lifecycle_phase = N_PPM_PHASE_1;
			err = NO_ERROR;
		}
		else
		{
			/** Set platform to Phase#U */
			ppm_context.lifecycle_phase = N_PPM_PHASE_U;
			err = N_PPM_ERR_NO_LIFECYCLE_PATTERN;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm ppm_manage_life_cycle(t_context *p_ctx)
{
	int_pltfrm 									err = GENERIC_ERR_NULL_PTR;

	/** Choose what to do depending on platform's life cycle */
	switch( ppm_context.lifecycle_phase )
	{
		case N_PPM_PHASE_0:
			/** SUP with STK */
			err = ppm_process_phase0(p_ctx);
			break;
		case N_PPM_PHASE_1:
			/** SUP with SSK/CSK and SLB launch */
			err = ppm_process_phase1(p_ctx);
			break;
		case N_PPM_PHASE_2:
			/** Platform must be shutdown as soon as possible */
			/** Go to shutdown mode */
			sbrm_shutdown(p_ctx);
			err = GENERIC_ERR_CRITICAL;
			break;
		default:
			/** Unknown phase, therefore only SUP+UID with SSK/CSK */
			err = ppm_process_phaseu(p_ctx);
			break;
	}
	/** End Of Function */
	return err;
}


/******************************************************************************/
/* End Of File */
