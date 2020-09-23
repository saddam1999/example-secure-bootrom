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
 * @file slbv_internal.h
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


#ifndef _SFLV_INTERNAL_H_
#define _SFLV_INTERNAL_H_

/** Global includes */
#include <stdint.h>
#include <stddef.h>
/** Other includes */
#include <common.h>
#include <errors.h>
/** Local includes */
#include <slbv.h>

/** External declarations */
/** Local declarations */

/** Defines *******************************************************************/
#define	C_SFLV_MAGIC_WORD1						0xf17ea991
#define	C_SFLV_MAGIC_WORD2						0xf17ea992



#ifdef _WITH_GPT_
#define GPT_GUID_SIZE 16
#define GPT_HEADER_LBA 1
#define GPT_HEADER_BYTES 92

#define MICRON_SPI_FLASH_CMD_RESET_ENABLE        0x66
#define MICRON_SPI_FLASH_CMD_MEMORY_RESET        0x99
#define MICRON_SPI_FLASH_CMD_READ                0x03
#define MICRON_SPI_FLASH_CMD_QUAD_FAST_READ      0x6b

								// top of board
// Modes 0-4 are handled in the ModeSelect Gate ROM		//       0123
#define MODESELECT_LOOP 0					// 0000  ----
#define MODESELECT_SPI0_FLASH_XIP 1				// 0001  _---
#define MODESELECT_SPI1_FLASH_XIP 2				// 0010  -_--
#define MODESELECT_CHIPLINK_TL_UH_XIP 3				// 0011  __--
#define MODESELECT_CHIPLINK_TL_C_XIP 4				// 0100  --_-
#define MODESELECT_ZSBL_SPI0_MMAP_FSBL_SPI0_MMAP 5		// 0101  _-_-
#define MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI0_MMAP_QUAD 6	// 0110  -__-
#define MODESELECT_ZSBL_SPI1_MMAP_QUAD_FSBL_SPI1_MMAP_QUAD 7	// 0111  ___-
#define MODESELECT_ZSBL_SPI1_SDCARD_FSBL_SPI1_SDCARD 8		// 1000  ---_
#define MODESELECT_ZSBL_SPI2_FLASH_FSBL_SPI2_FLASH 9		// 1001  _--_
#define MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI1_SDCARD 10	// 1010  -_-_
#define MODESELECT_ZSBL_SPI2_SDCARD_FSBL_SPI2_SDCARD 11		// 1011  __-_
#define MODESELECT_ZSBL_SPI1_FLASH_FSBL_SPI2_SDCARD 12		// 1100  --__
#define MODESELECT_ZSBL_SPI1_MMAP_QUAD_FSBL_SPI2_SDCARD 13	// 1101  -_--
#define MODESELECT_ZSBL_SPI0_FLASH_FSBL_SPI2_SDCARD 14		// 1110  -___
#define MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI2_SDCARD 15	// 1111  ____

#define GPT_BLOCK_SIZE 512

// Bit fields of error codes
#define ERROR_CODE_BOOTSTAGE (0xfUL << 60)
#define ERROR_CODE_TRAP (0xfUL << 56)
#define ERROR_CODE_ERRORCODE ((0x1UL << 56) - 1)
// Bit fields of mcause fields when compressed to fit into the errorcode field
#define ERROR_CODE_ERRORCODE_MCAUSE_INT (0x1UL << 55)
#define ERROR_CODE_ERRORCODE_MCAUSE_CAUSE ((0x1UL << 55) - 1)

#define ERROR_CODE_UNHANDLED_SPI_DEVICE 0x1
#define ERROR_CODE_UNHANDLED_BOOT_ROUTINE 0x2
#define ERROR_CODE_GPT_PARTITION_NOT_FOUND 0x3
#define ERROR_CODE_SPI_COPY_FAILED 0x4
#define ERROR_CODE_SD_CARD_CMD0 0x5
#define ERROR_CODE_SD_CARD_CMD8 0x6
#define ERROR_CODE_SD_CARD_ACMD41 0x7
#define ERROR_CODE_SD_CARD_CMD58 0x8
#define ERROR_CODE_SD_CARD_CMD16 0x9
#define ERROR_CODE_SD_CARD_CMD18 0xa
#define ERROR_CODE_SD_CARD_CMD18_CRC 0xb
#define ERROR_CODE_SD_CARD_UNEXPECTED_ERROR 0xc

// We are assuming that an error LED is connected to the GPIO pin
#define UX00BOOT_ERROR_LED_GPIO_PIN 15
#define UX00BOOT_ERROR_LED_GPIO_MASK (1 << 15)
#endif /* _WITH_GPT_ */
/** Enumerations **************************************************************/
typedef enum {
  UX00BOOT_ROUTINE_FLASH,  // Use SPI commands to read from flash one byte at a time
  UX00BOOT_ROUTINE_MMAP,  // Read from memory-mapped SPI region
  UX00BOOT_ROUTINE_MMAP_QUAD,  // Enable quad SPI mode and then read from memory-mapped SPI region
  UX00BOOT_ROUTINE_SDCARD,  // Initialize SD card controller and then use SPI commands to read one byte at a time
  UX00BOOT_ROUTINE_SDCARD_NO_INIT,  // Use SD SPI commands to read one byte at a time without initialization
} ux00boot_routine;

/** Application types */
typedef enum
{
	/**  */
	N_SLBV_APP_TYPE_MIN = 0,
	N_SLBV_APP_TYPE_REGULAR,
	N_SLBV_APP_TYPE_ENCRYPTED = 0x0fd4,
	N_SLBV_APP_TYPE_MAX

} e_application_type;


/** Structures ****************************************************************/
#ifdef _WITH_GPT_
typedef struct
{
  uint8_t bytes[GPT_GUID_SIZE];
} gpt_guid;


typedef struct
{
  uint64_t signature;
  uint32_t revision;
  uint32_t header_size;
  uint32_t header_crc;
  uint32_t reserved;
  uint64_t current_lba;
  uint64_t backup_lba;
  uint64_t first_usable_lba;
  uint64_t last_usable_lba;
  gpt_guid disk_guid;
  uint64_t partition_entries_lba;
  uint32_t num_partition_entries;
  uint32_t partition_entry_size;
  uint32_t partition_array_crc;
  // gcc will pad this struct to an alignment the matches the alignment of the
  // maximum member size, i.e. an 8-byte alignment.
  uint32_t padding;
} gpt_header;

// If either field is zero, the range is invalid (partitions can't be at LBA 0).
typedef struct
{
  uint64_t first_lba;
  uint64_t last_lba;  // Inclusive
} gpt_partition_range;

typedef struct
{
  gpt_guid partition_type_guid;
  gpt_guid partition_guid;
  uint64_t first_lba;
  uint64_t last_lba;
  uint64_t attributes;
  uint16_t name[36];  // UTF-16
} gpt_partition_entry;
_ASSERT_SIZEOF(gpt_partition_entry, 128);
#endif /* _WITH_GPT_ */


/** Functions *****************************************************************/
#ifdef _WITH_GPT_
gpt_partition_range gpt_find_partition_by_guid(const void* entries, const gpt_guid* guid, uint32_t num_entries);

static inline gpt_partition_range gpt_invalid_partition_range()
{
  return (gpt_partition_range) { .first_lba = 0, .last_lba = 0 };
}

static inline int gpt_is_valid_partition_range(gpt_partition_range range)
{
  return range.first_lba != 0 && range.last_lba != 0;
}
#endif /* _WITH_GPT_ */
/** Macros ********************************************************************/
#ifdef _WITH_GPT_
/** _DBY_YG_ */
#define _ASSERT_SIZEOF(type, size) \
  _Static_assert(sizeof(type) == (size), #type " must be " #size " bytes wide")
#define _ASSERT_OFFSETOF(type, member, offset) \
  _Static_assert(offsetof(type, member) == (offset), #type "." #member " must be at offset " #offset)
_ASSERT_SIZEOF(gpt_header, 96);
_ASSERT_OFFSETOF(gpt_header, disk_guid, 0x38);
_ASSERT_OFFSETOF(gpt_header, partition_array_crc, 0x58);
#undef _ASSERT_SIZEOF
#undef _ASSERT_OFFSETOF
#endif /* _WITH_GPT_ */

/**  */

#endif /* _SFLV_INTERNAL_H_ */

/******************************************************************************/
/* End Of File */
