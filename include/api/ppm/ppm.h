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
 * @file ppm.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


#ifndef _PPM_H_
#define _PPM_H_

/** Global includes */
#include <stddef.h>
#include <errors.h>
#include <common.h>
/** Other includes */
#include <km.h>
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
/** PPM errors base */
#define C_PPM_BASE_ERROR        				( N_PREFIX_PPM << C_PREFIX_OFFSET )

//#define	C_PPM_LIFECYCLE_PATTERN_SIZE_INBYTES	( 2 * sizeof(uint32_t) )
#define	C_PPM_LIFECYCLE_PATTERN_SIZE_INBYTES	( 1 * sizeof(uint8_t) )

///** Prefix of Life Cycle Pattern */
//#define	C_PPM_LIFECYCLE_PATTERN_PHASE_PFX_IDX	1
//#define	C_PPM_LIFECYCLE_PATTERN_PHASE_PFX		0x51F17E1C
///** Suffix of Life Cycle Pattern */
//#define	C_PPM_LIFECYCLE_PATTERN_PHASE_SFX_IDX	0
//#define	C_PPM_LIFECYCLE_PATTERN_PHASE1_SFX		0xF131D001
//#define	C_PPM_LIFECYCLE_PATTERN_PHASE2_SFX		0xDEAD0002

#define	C_PPM_LIFECYCLE_PATTERN_VIRGIN			C_PATTERN_VIRGIN_8BITS

/** Enumerations **************************************************************/
typedef enum
{
	/**  */
	N_PPM_PHASE_MIN = 0,
	N_PPM_PHASE_0 = N_PPM_PHASE_MIN,
	N_PPM_PHASE_1,
	N_PPM_PHASE_2,
	N_PPM_PHASE_U,
	N_PPM_PHASE_MAX = N_PPM_PHASE_U,
	N_PPM_PHASE_COUNT

} e_ppm_phase;

typedef enum
{
	/**  */
	N_PPM_ERR_MIN = C_PPM_BASE_ERROR,
	N_PPM_ERR_NO_LIFECYCLE_PATTERN,
	N_PPM_ERR_CANT_RETRIEVE_LCP,
	N_PPM_ERR_,
	N_PPM_ERR_MAX = N_PPM_ERR_,
	N_PPM_ERR_COUNT

} e_ppm_error;


/** Structures ****************************************************************/
typedef struct
{
	/** Platform phase */
	e_ppm_phase									lifecycle_phase;
	/** RMA Mode enabled ? */
	uint32_t									rma_enable;
	/** Key for current SUP session */
	e_km_key_index								session_key;

} t_ppm_context;

/** Functions *****************************************************************/
int_pltfrm ppm_init(void *p_ctx, void *p_in, uint32_t length_in);
int_pltfrm ppm_shutdown(void *p_ctx);
int_pltfrm ppm_get_life_cycle(t_context *p_ctx);
int_pltfrm ppm_manage_life_cycle(t_context *p_ctx);



/** Macros ********************************************************************/

#endif /* _PPM_H_ */

/******************************************************************************/
/* End Of File */
