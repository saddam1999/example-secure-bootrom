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
 * @file sbrm.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


/** Global includes */
#include <stdio.h>
#include <string.h>
#include <common.h>
#include <errors.h>
#include <memory.h>
#include <metal/cpu.h>
#include <metal/shutdown.h>
/** Other includes */
#include <km.h>
#include <pi.h>
#include <ppm.h>
#include <sp.h>
#include <sp_internal.h>
#include <slbv.h>
#include <daim.h>
/** Local includes */
#include <sbrm.h>



/** External declarations */
extern uint_pltfrm __sbrm_free_start_addr;
extern uint_pltfrm __sbrm_free_end_addr;
extern uint_pltfrm __fake_otp_size;
extern uint_pltfrm __otp_start;
#ifdef _FPGA_SPECIFIC_
#endif /** _FPGA_SPECIFIC_ */
/** Local declarations */
__attribute__((section(".bss"))) volatile t_sbrm_context sbrm_context;


/******************************************************************************/
int_pltfrm sbrm_init(void *p_ctx, void *p_in, uint32_t length_in)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint32_t									i;
	uint32_t									j;

	/** Check input parameter */
	if ( NULL == p_ctx )
	{
		/** Input pointer is null, not good */
		err = GENERIC_ERR_NULL_PTR;
		goto sbrm_init_out;
	}
	else
	{
		t_context								*p_context = (t_context*)p_ctx;

		/** First zero-ize local context */
		memset((void*)&sbrm_context, 0x00, sizeof(t_sbrm_context));
	    /** Lets get the CPU and and its interrupt */
	    sbrm_context.p_cpu = metal_cpu_get(metal_cpu_get_current_hartid());
	    if( NULL == sbrm_context.p_cpu )
	    {
	        /**  */
	        err = N_SBRM_ERR_CPU_NOT_FOUND;
	        goto sbrm_init_out;
	    }
	    /** Retrieve interruption controller according to CPU used */
	    sbrm_context.p_cpu_intr = metal_cpu_interrupt_controller(sbrm_context.p_cpu);
	    if( NULL == sbrm_context.p_cpu_intr )
	    {
	        /**  */
	        err = N_SBRM_ERR_CPU_IRQ_NOT_FOUND;
	        goto sbrm_init_out;
	    }
	    /** Initialize interruption */
	    metal_interrupt_init(sbrm_context.p_cpu_intr);
#if defined (METAL_RISCV_PLIC0)
	    /** Check if this target has a plic */
	    sbrm_context.p_pclic = metal_interrupt_get_controller(METAL_PLIC_CONTROLLER, 0);
#elif defined (METAL_SIFIVE_CLIC0)
	    /** Check we this target has a plic */
	    sbrm_context.p_pclic = metal_interrupt_get_controller(METAL_CLIC_CONTROLLER, 0);
#else
#error Either PLIC, either CLIC must be defined !!!!
#endif /* METAL_SIFIVE_CLIC0 */
		if( !sbrm_context.p_pclic )
		{
			err = N_SBRM_ERR_PLIC_NOT_FOUND;
			goto sbrm_init_out;
		}
		/** Initialize CLINT/CLIC */
		metal_interrupt_init(sbrm_context.p_pclic);
	    /** Initialize CRC32 reference array */
	    /** Zero-ize array */
		memset((void*)sbrm_context.crc_ref_table, 0x00, sizeof(sbrm_context.crc_ref_table));
		/** Compute CRC table for this session */
		for(i = 0;i < C_SBRM_CRC_TABLE_SIZE_INT;i++ )
		{
			/** Remainder from polynomial division */
			sbrm_context.crc_ref_table[i] = i;
			for( j = 0;j < 8;j++ )
			{
				/** Value is odd or even */
				if( sbrm_context.crc_ref_table[i] & 0x01 )
				{
					/** Odd */
					sbrm_context.crc_ref_table[i] >>= 1;
					sbrm_context.crc_ref_table[i] ^= C_SIFIVE_POLYNOMIAL;
				}
				else
				{
					/** Even - nothing to be done */
					sbrm_context.crc_ref_table[i] >>= 1;
				}
			}
		}
	    /** Assign iRAM boundaries */
	    p_context->free_ram_start = (uint_pltfrm)&__sbrm_free_start_addr;
	    p_context->free_ram_end = (uint_pltfrm)&__sbrm_free_end_addr;
#ifdef _FPGA_SPECIFIC_
	    p_context->otp._base_address = (uint_pltfrm)&__otp_start;
	    p_context->otp._size = (uint_pltfrm)&__fake_otp_size;
#endif /* _FPGA_SPECIFIC_ */
	    /** Assignment to global context structure */
	    p_context->p_sbrm_context = (volatile void*)&sbrm_context;
	    /** No error */
	    err = NO_ERROR;
	}
sbrm_init_out:
	/** End of function */
	return err;
}

/******************************************************************************/
__attribute__((noreturn)) void sbrm_shutdown(void *p_ctx)
{
	/** Ask for Shutdown to PW Management */
	metal_shutdown(0);
	/** End Of Function - should not be reached */
}

/******************************************************************************/
int_pltfrm sbrm_read_otp(t_context *p_ctx, uint_pltfrm offset, uint8_t *p_data, uint32_t length)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx || !p_data )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	/** Check input parameter */
	else if( p_ctx->otp._size < ( ( offset - p_ctx->otp._base_address ) + length ) )
	{
		/**  */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Simple copy for now - OTP controller dependent */
		memcpy((void*)p_data, (const void*)offset, length );
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sbrm_write_otp(t_context *p_ctx, uint_pltfrm offset, const uint8_t *p_data, uint32_t length)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx || !p_data )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	/** Check input parameter */
	else if( p_ctx->otp._size < ( ( offset - p_ctx->otp._base_address ) + length ) )
	{
		/**  */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Simple copy for now - OTP controller dependent */
		memcpy((void*)offset, (const void*)p_data, length);
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sbrm_check_rom_crc(void)
{
	/**  */
	/** End Of Function */
	return NO_ERROR;
}

/******************************************************************************/
void sbrm_erase_contexts(t_context *p_context)
{
	/** Zero-ize contexts */
	if ( NULL != p_context )
	{
		/** Key Management */
		if ( NULL != p_context->p_km_context )
		{
			memset((void*)p_context->p_km_context, 0x00, sizeof(t_km_context));
		}
		/** Platform Phase Management */
		if ( NULL != p_context->p_ppm_context )
		{
			memset((void*)p_context->p_ppm_context, 0x00, sizeof(t_ppm_context));
		}
		/** Secure Boot Core Management */
		if ( NULL != p_context->p_sbrm_context )
		{
			memset((void*)p_context->p_sbrm_context, 0x00, sizeof(t_sbrm_context));
		}
		/** Secure Flexible Loader Verification */
		if ( NULL != p_context->p_slbv_context )
		{
			memset((void*)p_context->p_slbv_context, 0x00, sizeof(t_slbv_context));
		}
		/** Secure Protocol */
		if ( NULL != p_context->p_sp_context )
		{
			memset((void*)p_context->p_sp_context, 0x00, sizeof(t_sp_context));
		}
		/** Global context */
		memset((void*)p_context, 0x00, sizeof(t_context));
	}
	/** End Of Function */
	return;
}

/******************************************************************************/
int_pltfrm sbrm_get_uid(t_context *p_ctx, uint8_t *p_uid)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input parameter */
	if ( !p_uid || !p_ctx )
	{
		/** Pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Read UID from OTP */
		err = sbrm_read_otp(p_ctx, C_OTP_UID_OFST, p_uid, C_OTP_UID_SIZE);
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sbrm_get_sbr_version(uint32_t *p_version)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input parameter */
	if ( !p_version )
	{
		/** Pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Set version edit number */
		*p_version = ( SBR_VERSION_EDIT << C_SBR_VERSION_EDIT_OFST ) & C_SBR_VERSION_EDIT_MASK;
		/** Set version minor number */
		*p_version |= ( ( SBR_VERSION_MINOR << C_SBR_VERSION_MINOR_OFST ) & C_SBR_VERSION_MINOR_MASK );
		/** Set version major number */
		*p_version |= ( ( SBR_VERSION_MAJOR << C_SBR_VERSION_MAJOR_OFST ) & C_SBR_VERSION_MAJOR_MASK );
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sbrm_get_sbr_ref_version(uint32_t *p_version)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input parameter */
	if ( !p_version )
	{
		/** Pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Set version edit number */
		*p_version = ( SBR_REF_VERSION_EDIT << C_SBR_REF_VERSION_EDIT_OFST ) & C_SBR_REF_VERSION_EDIT_MASK;
		/** Set version minor number */
		*p_version |= ( ( SBR_REF_VERSION_MINOR << C_SBR_REF_VERSION_MINOR_OFST ) & C_SBR_REF_VERSION_MINOR_MASK );
		/** Set version major number */
		*p_version |= ( ( SBR_REF_VERSION_MAJOR << C_SBR_REF_VERSION_MAJOR_OFST ) & C_SBR_REF_VERSION_MAJOR_MASK );
		/** No error */
		err = NO_ERROR;
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
__attribute__((naked)) void sbrm_platform_reset(t_context *p_ctx)
{
	/** Zero-ize contexts */
	if ( !p_ctx )
	{
		sbrm_erase_contexts(p_ctx);
	}
	/** Ask for platform reset */

	/** Endless loop - shouldn't be needed */
	while( 1 );
	/** End Of Function */
	return;
}

/******************************************************************************/
__attribute__((naked)) void sbrm_platform_shutdown(t_context *p_ctx)
{
	/** Zero-ize contexts */
	if ( !p_ctx )
	{
		sbrm_erase_contexts(p_ctx);
	}
	/** Go into "shutdown power mode" */
	metal_shutdown(0);
	/** Endless loop - shouldn't be needed */
	while( 1 );
	/** End Of Function */
	return;
}

/******************************************************************************/

/* End Of File */
