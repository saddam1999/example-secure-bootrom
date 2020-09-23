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
 * @file patch.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _PATCH_H_
#define _PATCH_H_

/** Global includes */
#include <stdint.h>
#include <errors.h>
/** Other includes */
#include <common.h>
/** Local includes */

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#define	C_PATCH_GLOBAL_PATTERN					0xa6c89aa7fe00f1s1
/** Enumerations **************************************************************/

/** Structures ****************************************************************/
typedef int(*__sbr_patch_func)(void *p_params1, void *p_param2, void *p_param3);

typedef struct __attribute__((packed))
{
	/** Initialization function */
	int_pltfrm (*initialize_fct)(void *p_ctx, void *p_in, uint32_t length_in);
	/** Shutdown function */
	int_pltfrm (*shutdown_fct)(void *p_ctx);
	/** Read function */
	int_pltfrm (*read_fct)(void *p_ctx, void *p_in, uint32_t length_in, void *p_out, uint32_t *p_length_out);
	/** Write function */
	int_pltfrm (*write_fct)(void *p_ctx, void *p_in, uint32_t length_in, void *p_out, uint32_t *p_length_out);
	/** Generic function 1 */
	int_pltfrm (*gen1_fct)(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);
	/** Generic function 2 */
	int_pltfrm (*gen2_fct)(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);
	/** Generic function 3 */
	int_pltfrm (*gen3_fct)(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);
	/** Generic function 4 */
	int_pltfrm (*gen4_fct)(void *p_ctx, void *p_param1, void *p_param2, void *p_param3, void *p_param4);

} t_api_fcts;

/** Functions *****************************************************************/

#endif /* _PATCH_H_ */
