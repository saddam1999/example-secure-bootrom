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
 * @file errors.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */

#ifndef _ERRORS_H_
#define _ERRORS_H_

/** Global includes */
/** Other includes */
/** Local includes */


/** Defines *******************************************************************/
#define C_PREFIX_OFFSET							24
/** Enumeration ***************************************************************/

typedef enum
{
	/**  */
	N_PREFIX_MIN = 0,
	N_PREFIX_GENERIC,
	N_PREFIX_SP,
	N_PREFIX_PPM,
	N_PREFIX_SBRM,
	N_PREFIX_SLBV,
	N_PREFIX_KM,
	N_PREFIX_PI,
	N_PREFIX_DAIM,
	N_PREFIX_MAX = N_PREFIX_DAIM,

} e_sbr_prefix_errors;

/** SP errors base */
#define C_GENERIC_BASE_ERROR        				( N_PREFIX_GENERIC << C_PREFIX_OFFSET )

typedef enum
{
	/**  */
	NO_ERROR = 0,
	/**  */
	N_SBR_ERR_MIN = C_GENERIC_BASE_ERROR,
	GENERIC_ERR_INVAL,
	GENERIC_ERR_OUT_OF_RANGE,
	GENERIC_ERR_NULL_PTR,
	GENERIC_ERR_CRITICAL,
	GENERIC_ERR_NOSCRATCHPAD,
	GENERIC_ERR_NOT_SUPPORTED,
	GENERIC_ERR_RESET,
	GENERIC_ERR_SHUTDOWN,
	GENERIC_ERR_UNKNOWN,
	N_SBR_ERR_MAX = GENERIC_ERR_UNKNOWN,

} e_sbr_errors;

/** Structures ****************************************************************/

/** Macros ********************************************************************/


#endif /* _ERRORS_H_ */
