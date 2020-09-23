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
 * @file ppm_internal.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


/** Global includes */
#include <errors.h>
#include <common.h>
/** Other includes */
#include <otp_mapping.h>
#include <sp.h>
#include <sp_internal.h>
#include <slbv.h>
#include <sbrm.h>
/** Local includes */
#include <ppm.h>
#include <ppm_internal.h>


/** External declarations */
extern t_ppm_context ppm_context;
/** Local declarations */


/******************************************************************************/
int_pltfrm ppm_process_phase0(t_context *p_ctx)
{
	/** Call secure protocol function */
	/** End Of Function */
	return sp_launch_sup(p_ctx, N_SP_KEY_STK);
}


/******************************************************************************/


/******************************************************************************/
int_pltfrm ppm_rma_mode(t_context *p_ctx)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Read register to check for RMA_PMU boot mode */
		err = sbrm_read_otp(p_ctx, C_OTP_RMA_PMU_OFST, (uint8_t*)&ppm_context.rma_enable, C_OTP_RMA_PMU_SIZE);
		if( err )
		{
			/** OTP can not been read, critical error */
			ppm_context.rma_enable = 0;
			err = GENERIC_ERR_CRITICAL;
			goto ppm_rma_mode_out;
		}
		else if( C_OTP_RMA_PMU_PATTERN == ( C_OTP_RMA_PMU_PATTERN_MASK & ppm_context.rma_enable ) )
		{
			/** RMA mode enabled */
			goto ppm_rma_mode_out;
		}
		/** Now check for RMA_CSK */
		err = sbrm_read_otp(p_ctx, C_OTP_RMA_CSK_OFST, (uint8_t*)&ppm_context.rma_enable, C_OTP_RMA_CSK_SIZE);
		if( err )
		{
			/** OTP can not been read, critical error */
			ppm_context.rma_enable = 0;
			err = GENERIC_ERR_CRITICAL;
			goto ppm_rma_mode_out;
		}
		else if( C_OTP_RMA_CSK_PATTERN == ( C_OTP_RMA_CSK_PATTERN_MASK & ppm_context.rma_enable ) )
		{

		}
		else
		{
			/** RMA_mode disabled */
			ppm_context.rma_enable = 0;
		}
	}
ppm_rma_mode_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm ppm_process_phase1(t_context *p_ctx)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	t_sp_context								*p_sp_context;
	t_km_context								*p_km_context;

	/** Check input parameter */
	if ( !p_ctx || !p_ctx->p_sp_context )
	{
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		p_sp_context = (t_sp_context*)p_ctx->p_sp_context;
		p_km_context = (t_km_context*)p_ctx->p_km_context;

		/** 1st, Check if CSK is present and valid - mandatory for S21FW check and launch */
		err = km_check_key((t_context*)p_ctx, N_KM_KEYID_CSK);
		if( ( N_KM_ERR_NO_KEY == err ) &&
			( N_SP_STATE_DISABLE != p_sp_context->state ) &&
			( K_KM_SLOT_COUNT > p_km_context->index_free_csk ) )
		{
			/** Check if RMA mode is asked */
			err = ppm_rma_mode(p_ctx);
			if( err )
			{
				/**  */
				goto ppm_process_phase1_out;
			}
			/** If not, launch SUP session with CUK - SUP_REQ is not checked */
			err = sp_launch_sup(p_ctx, N_KM_KEYID_CUK);
			/** Check returned value */
			if( err )
			{
				/** Reset platform immediately */
				sbrm_platform_reset(p_ctx);
				/** Wait for reset */
				while( 1 );
			}
		}
		else if( err )
		{
			/** If SUP_DISABLE has been set, reset platform */
			/** Reset platform immediately */
			sbrm_platform_reset(p_ctx);
			/** Wait for reset */
			while( 1 );
		}
		else
		{
			/** CSK is present and valid, let's move on */
			ppm_context.session_key = N_KM_KEYID_CSK;
		}
		/** Now check SUP_REQ */

		/** SUP session without UID */
		err = sp_launch_sup(p_ctx, ppm_context.session_key);
		/** Check returned value */
		if ( N_SP_ERR_RESET_PLATFORM == err )
		{
			/** Reset platform immediately */
			sbrm_platform_reset(p_ctx);
			/** Wait for reset */
		}
		else if ( N_SP_ERR_SHUTDOWN_PLATFROM == err )
		{
			/** Set platform in shutdown mode immediately */
			sbrm_shutdown(p_ctx);
		}
		else
		{
			/** Enter SLB check and launch procedure if no specific error is returned */
			err = slbv_process((t_context*)p_ctx);
		}
	}
ppm_process_phase1_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm ppm_process_phaseu(t_context *p_ctx)
{
	/** Call secure protocol function */
	/** End Of Function */
	return sp_launch_sup(p_ctx, N_SP_KEY_SSK_CSK_UID);
}

/******************************************************************************/
/* End Of File */
