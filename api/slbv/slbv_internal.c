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
 * @file slbv_internal.c
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
#include <patch.h>
#include <otp_mapping.h>
/** Other includes */
/** Local includes */
#include <slbv.h>
#include <slbv_internal.h>

/** External declarations */
extern t_slbv_context slbv_context;
/** Local declarations */
#ifdef _WITH_GPT_
// GPT represents GUIDs with the first three blocks as little-endian
// c12a7328-f81f-11d2-ba4b-00a0c93ec93b
const gpt_guid gpt_guid_efi = {{
  0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b
}};
// 5b193300-fc78-40cd-8002-e86c45580b47
const gpt_guid gpt_guid_sifive_fsbl = {{
  0x00, 0x33, 0x19, 0x5b, 0x78, 0xfc, 0xcd, 0x40, 0x80, 0x02, 0xe8, 0x6c, 0x45, 0x58, 0x0b, 0x47
}};
// 2e54b353-1271-4842-806f-e436d6af6985
const gpt_guid gpt_guid_sifive_bare_metal = {{
  0x53, 0xb3, 0x54, 0x2e, 0x71, 0x12, 0x42, 0x48, 0x80, 0x6f, 0xe4, 0x36, 0xd6, 0xaf, 0x69, 0x85
}};
#endif /* _WITH_GPT_ */

#ifdef _WITH_GPT_
/******************************************************************************/
int32_t guid_equal(const gpt_guid* a, const gpt_guid* b)
{
  for (int i = 0; i < GPT_GUID_SIZE; i++) {
    if (a->bytes[i] != b->bytes[i]) {
return FALSE;
    }
  }
  return TRUE;
}

/******************************************************************************/
/**
 * Search the given block of partition entries for a partition with the given
 * GUID. Return a range of [0, 0] to indicate that the partition was not found.
 */
gpt_partition_range gpt_find_partition_by_guid(const void* entries, const gpt_guid* guid, uint32_t num_entries)
{
  gpt_partition_entry* gpt_entries = (gpt_partition_entry*) entries;
  for (uint32_t i = 0; i < num_entries; i++) {
    if (guid_equal(&gpt_entries[i].partition_type_guid, guid)) {
      return (gpt_partition_range) {
        .first_lba = gpt_entries[i].first_lba,
        .last_lba = gpt_entries[i].last_lba,
      };
    }
  }
  return (gpt_partition_range) { .first_lba = 0, .last_lba = 0 };
}

/******************************************************************************/
int32_t get_boot_spi_device(uint32_t mode_select)
{
  int32_t spi_device;


  switch( mode_select )
  {
    case MODESELECT_ZSBL_SPI0_MMAP_FSBL_SPI0_MMAP:
    case MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI0_MMAP_QUAD:
    case MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI1_SDCARD:
    case MODESELECT_ZSBL_SPI0_FLASH_FSBL_SPI2_SDCARD:
    case MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI2_SDCARD:
      spi_device = 0;
      break;
    case MODESELECT_ZSBL_SPI1_MMAP_QUAD_FSBL_SPI1_MMAP_QUAD:
    case MODESELECT_ZSBL_SPI1_SDCARD_FSBL_SPI1_SDCARD:
    case MODESELECT_ZSBL_SPI1_FLASH_FSBL_SPI2_SDCARD:
    case MODESELECT_ZSBL_SPI1_MMAP_QUAD_FSBL_SPI2_SDCARD:
      spi_device = 1;
      break;
    case MODESELECT_ZSBL_SPI2_FLASH_FSBL_SPI2_FLASH:
    case MODESELECT_ZSBL_SPI2_SDCARD_FSBL_SPI2_SDCARD:
      spi_device = 2;
      break;
    default:
      spi_device = -1;
      break;
  }
  return spi_device;
}

/******************************************************************************/
ux00boot_routine get_boot_routine(uint32_t mode_select)
{
  ux00boot_routine boot_routine = 0;

  switch (mode_select)
  {
    case MODESELECT_ZSBL_SPI2_FLASH_FSBL_SPI2_FLASH:
    case MODESELECT_ZSBL_SPI1_FLASH_FSBL_SPI2_SDCARD:
    case MODESELECT_ZSBL_SPI0_FLASH_FSBL_SPI2_SDCARD:
      boot_routine = UX00BOOT_ROUTINE_FLASH;
      break;
    case MODESELECT_ZSBL_SPI0_MMAP_FSBL_SPI0_MMAP:
      boot_routine = UX00BOOT_ROUTINE_MMAP;
      break;
    case MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI0_MMAP_QUAD:
    case MODESELECT_ZSBL_SPI1_MMAP_QUAD_FSBL_SPI1_MMAP_QUAD:
    case MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI1_SDCARD:
    case MODESELECT_ZSBL_SPI1_MMAP_QUAD_FSBL_SPI2_SDCARD:
    case MODESELECT_ZSBL_SPI0_MMAP_QUAD_FSBL_SPI2_SDCARD:
      boot_routine = UX00BOOT_ROUTINE_MMAP_QUAD;
      break;
    case MODESELECT_ZSBL_SPI1_SDCARD_FSBL_SPI1_SDCARD:
    case MODESELECT_ZSBL_SPI2_SDCARD_FSBL_SPI2_SDCARD:
      boot_routine = UX00BOOT_ROUTINE_SDCARD;
      break;
  }
  return boot_routine;
}

//==============================================================================
// UX00 boot routine functions
//==============================================================================
//------------------------------------------------------------------------------
// SD Card
//------------------------------------------------------------------------------
int32_t initialize_sd(spi_ctrl* spictrl, uint32_t peripheral_input_khz, int32_t skip_sd_init_commands)
{
  int32_t error = sd_init(spictrl, peripheral_input_khz, skip_sd_init_commands);
  if (error) {
    switch (error) {
      case SD_INIT_ERROR_CMD0: return ERROR_CODE_SD_CARD_CMD0;
      case SD_INIT_ERROR_CMD8: return ERROR_CODE_SD_CARD_CMD8;
      case SD_INIT_ERROR_ACMD41: return ERROR_CODE_SD_CARD_ACMD41;
      case SD_INIT_ERROR_CMD58: return ERROR_CODE_SD_CARD_CMD58;
      case SD_INIT_ERROR_CMD16: return ERROR_CODE_SD_CARD_CMD16;
      default: return ERROR_CODE_SD_CARD_UNEXPECTED_ERROR;
    }
  }
  return 0;
}

/******************************************************************************/
gpt_partition_range find_sd_gpt_partition(
  spi_ctrl* spictrl,
  uint64_t partition_entries_lba,
  uint32_t num_partition_entries,
  uint32_t partition_entry_size,
  const gpt_guid* partition_type_guid,
  void* block_buf  // Used to temporarily load blocks of SD card
)
{
  // Exclusive end
  uint64_t partition_entries_lba_end = (
    partition_entries_lba +
    (num_partition_entries * partition_entry_size + GPT_BLOCK_SIZE - 1) / GPT_BLOCK_SIZE
  );
  for (uint64_t i = partition_entries_lba; i < partition_entries_lba_end; i++) {
    sd_copy(spictrl, block_buf, i, 1);
    gpt_partition_range range = gpt_find_partition_by_guid(
      block_buf, partition_type_guid, GPT_BLOCK_SIZE / partition_entry_size
    );
    if (gpt_is_valid_partition_range(range)) {
      return range;
    }
  }
  return gpt_invalid_partition_range();
}


/******************************************************************************/
int32_t decode_sd_copy_error(int32_t error)
{
  switch (error) {
    case SD_COPY_ERROR_CMD18: return ERROR_CODE_SD_CARD_CMD18;
    case SD_COPY_ERROR_CMD18_CRC: return ERROR_CODE_SD_CARD_CMD18_CRC;
    default: return ERROR_CODE_SD_CARD_UNEXPECTED_ERROR;
  }
}


/******************************************************************************/
int32_t load_sd_gpt_partition(spi_ctrl* spictrl, void* dst, const gpt_guid* partition_type_guid)
{
  uint8_t gpt_buf[GPT_BLOCK_SIZE];
  int32_t error;
  error = sd_copy(spictrl, gpt_buf, GPT_HEADER_LBA, 1);
  if (error) return decode_sd_copy_error(error);

  gpt_partition_range part_range;
  {
    // header will be overwritten by find_sd_gpt_partition(), so locally
    // scope it.
    gpt_header* header = (gpt_header*) gpt_buf;
    part_range = find_sd_gpt_partition(
      spictrl,
      header->partition_entries_lba,
      header->num_partition_entries,
      header->partition_entry_size,
      partition_type_guid,
      gpt_buf
    );
  }

  if (!gpt_is_valid_partition_range(part_range)) {
    return ERROR_CODE_GPT_PARTITION_NOT_FOUND;
  }

  error = sd_copy(
    spictrl,
    dst,
    part_range.first_lba,
    part_range.last_lba + 1 - part_range.first_lba
  );
  if (error) return decode_sd_copy_error(error);
  return 0;
}

//------------------------------------------------------------------------------
// SPI flash
//------------------------------------------------------------------------------
/**
 * Set up SPI for direct, non-memory-mapped access.
 */
inline int32_t initialize_spi_flash_direct(spi_ctrl* spictrl, uint32_t spi_clk_input_khz)
{
  // Max desired SPI clock is 10MHz
  spictrl->sckdiv = spi_min_clk_divisor(spi_clk_input_khz, 10000);

  spictrl->fctrl.en = 0;

  spi_txrx(spictrl, MICRON_SPI_FLASH_CMD_RESET_ENABLE);
  spi_txrx(spictrl, MICRON_SPI_FLASH_CMD_MEMORY_RESET);

  return 0;
}


/******************************************************************************/
inline int32_t _initialize_spi_flash_mmap(spi_ctrl* spictrl, uint32_t spi_clk_input_khz, uint32_t pad_cnt, uint32_t data_proto, uint32_t command_code)
{
  // Max desired SPI clock is 10MHz
  spictrl->sckdiv = spi_min_clk_divisor(spi_clk_input_khz, 10000);

  spictrl->fctrl.en = 0;

  spi_txrx(spictrl, MICRON_SPI_FLASH_CMD_RESET_ENABLE);
  spi_txrx(spictrl, MICRON_SPI_FLASH_CMD_MEMORY_RESET);

  spictrl->ffmt.raw_bits = ((spi_reg_ffmt) {
    .cmd_en = 1,
    .addr_len = 3,
    .pad_cnt = pad_cnt,
    .command_proto = SPI_PROTO_S,
    .addr_proto = SPI_PROTO_S,
    .data_proto = data_proto,
    .command_code = command_code,
  }).raw_bits;

  spictrl->fctrl.en = 1;
  __asm__ __volatile__ ("fence io, io");
  return 0;
}


/******************************************************************************/
int32_t initialize_spi_flash_mmap_single(spi_ctrl* spictrl, uint32_t spi_clk_input_khz)
{
  return _initialize_spi_flash_mmap(spictrl, spi_clk_input_khz, 0, SPI_PROTO_S, MICRON_SPI_FLASH_CMD_READ);
}


/******************************************************************************/
int32_t initialize_spi_flash_mmap_quad(spi_ctrl* spictrl, uint32_t spi_clk_input_khz)
{
  return _initialize_spi_flash_mmap(spictrl, spi_clk_input_khz, 8, SPI_PROTO_Q, MICRON_SPI_FLASH_CMD_QUAD_FAST_READ);
}


//------------------------------------------------------------------------------
// SPI flash memory-mapped
/******************************************************************************/
gpt_partition_range find_mmap_gpt_partition(const void* gpt_base, const gpt_guid* partition_type_guid)
{
  gpt_header* header = (gpt_header*) ((uintptr_t) gpt_base + GPT_HEADER_LBA * GPT_BLOCK_SIZE);
  gpt_partition_range range;
  range = gpt_find_partition_by_guid(
    (const void*) ((uintptr_t) gpt_base + header->partition_entries_lba * GPT_BLOCK_SIZE),
    partition_type_guid,
    header->num_partition_entries
  );
  if (gpt_is_valid_partition_range(range)) {
    return range;
  }
  return gpt_invalid_partition_range();
}


/**
 * Load GPT partition from memory-mapped GPT image.
 */
/******************************************************************************/
int32_t load_mmap_gpt_partition(const void* gpt_base, void* payload_dest, const gpt_guid* partition_type_guid)
{
  gpt_partition_range range = find_mmap_gpt_partition(gpt_base, partition_type_guid);
  if (!gpt_is_valid_partition_range(range)) {
    return ERROR_CODE_GPT_PARTITION_NOT_FOUND;
  }
  memcpy(
    payload_dest,
    (void*) ((uintptr_t) gpt_base + range.first_lba * GPT_BLOCK_SIZE),
    (range.last_lba + 1 - range.first_lba) * GPT_BLOCK_SIZE
  );
  return 0;
}


//------------------------------------------------------------------------------
// SPI flash non-memory-mapped

/******************************************************************************/
gpt_partition_range find_spiflash_gpt_partition(
  spi_ctrl* spictrl,
  uint64_t partition_entries_lba,
  uint32_t num_partition_entries,
  uint32_t partition_entry_size,
  const gpt_guid* partition_type_guid,
  void* block_buf  // Used to temporarily load blocks of SD card
)
{
  // Exclusive end
  uint64_t partition_entries_lba_end = (
    partition_entries_lba +
    (num_partition_entries * partition_entry_size + GPT_BLOCK_SIZE - 1) / GPT_BLOCK_SIZE
  );
  for (uint64_t i = partition_entries_lba; i < partition_entries_lba_end; i++) {
    spi_copy(spictrl, block_buf, i * GPT_BLOCK_SIZE, GPT_BLOCK_SIZE);
    gpt_partition_range range = gpt_find_partition_by_guid(
      block_buf, partition_type_guid, GPT_BLOCK_SIZE / partition_entry_size
    );
    if (gpt_is_valid_partition_range(range)) {
      return range;
    }
  }
  return gpt_invalid_partition_range();
}


/**
 * Load GPT partition from SPI flash.
 */
/******************************************************************************/
int32_t load_spiflash_gpt_partition(spi_ctrl* spictrl, void* dst, const gpt_guid* partition_type_guid)
{
  uint8_t gpt_buf[GPT_BLOCK_SIZE];
  int32_t error;
  error = spi_copy(spictrl, gpt_buf, GPT_HEADER_LBA * GPT_BLOCK_SIZE, GPT_HEADER_BYTES);
  if (error) return ERROR_CODE_SPI_COPY_FAILED;

  gpt_partition_range part_range;
  {
    gpt_header* header = (gpt_header*) gpt_buf;
    part_range = find_spiflash_gpt_partition(
      spictrl,
      header->partition_entries_lba,
      header->num_partition_entries,
      header->partition_entry_size,
      partition_type_guid,
      gpt_buf
    );
  }

  if (!gpt_is_valid_partition_range(part_range)) {
    return ERROR_CODE_GPT_PARTITION_NOT_FOUND;
  }

  error = spi_copy(
    spictrl,
    dst,
    part_range.first_lba * GPT_BLOCK_SIZE,
    (part_range.last_lba + 1 - part_range.first_lba) * GPT_BLOCK_SIZE
  );
  if (error) return ERROR_CODE_SPI_COPY_FAILED;
  return 0;
}

/******************************************************************************/
void ux00boot_fail(long code, int32_t trap)
{
  if (read_csr(mhartid) == NONSMP_HART) {
    // Print32_t error code to UART
    UART0_REG(UART_REG_TXCTRL) = UART_TXEN;

    // Error codes are formatted as follows:
    // [63:60]    [59:56]  [55:0]
    // bootstage  trap     errorcode
    // If trap == 1, then errorcode is actually the mcause register with the
    // interrupt bit shifted to bit 55.
    uint64_t error_code = 0;
    if (trap) {
      error_code = INSERT_FIELD(error_code, ERROR_CODE_ERRORCODE_MCAUSE_CAUSE, code);
      if (code < 0) {
        error_code = INSERT_FIELD(error_code, ERROR_CODE_ERRORCODE_MCAUSE_INT, 0x1UL);
      }
    } else {
      error_code = code;
    }
    uint64_t formatted_code = 0;
    formatted_code = INSERT_FIELD(formatted_code, ERROR_CODE_BOOTSTAGE, UX00BOOT_BOOT_STAGE);
    formatted_code = INSERT_FIELD(formatted_code, ERROR_CODE_TRAP, trap);
    formatted_code = INSERT_FIELD(formatted_code, ERROR_CODE_ERRORCODE, error_code);

    uart_puts((void*) UART0_CTRL_ADDR, "Error 0x");
    uart_put_hex((void*) UART0_CTRL_ADDR, formatted_code >> 32);
    uart_put_hex((void*) UART0_CTRL_ADDR, formatted_code);
  }

  // Turn on LED
  atomic_fetch_or(&GPIO_REG(GPIO_OUTPUT_VAL), UX00BOOT_ERROR_LED_GPIO_MASK);
  atomic_fetch_or(&GPIO_REG(GPIO_OUTPUT_EN), UX00BOOT_ERROR_LED_GPIO_MASK);
  atomic_fetch_or(&GPIO_REG(GPIO_OUTPUT_XOR), UX00BOOT_ERROR_LED_GPIO_MASK);

  while (1);
}

//==============================================================================
// Public functions
//==============================================================================
/**
 * Load GPT partition match specified partition type into specified memory.
 *
 * Read from mode select device to determine which bulk storage medium to read
 * GPT image from, and properly initialize the bulk storage based on type.
 */
void ux00boot_load_gpt_partition(void* dst, const gpt_guid* partition_type_guid, uint32_t peripheral_input_khz)
{
  uint32_t mode_select = *((volatile uint32_t*) MODESELECT_MEM_ADDR);

  spi_ctrl* spictrl = NULL;
  void* spimem = NULL;

  int32_t spi_device = get_boot_spi_device(mode_select);
  ux00boot_routine boot_routine = get_boot_routine(mode_select);

  switch(spi_device)
  {
    case 0:
      spictrl = (spi_ctrl*) SPI0_CTRL_ADDR;
      spimem = (void*) SPI0_MEM_ADDR;
      break;
    case 1:
      spictrl = (spi_ctrl*) SPI1_CTRL_ADDR;
      spimem = (void*) SPI1_MEM_ADDR;
      break;
    case 2:
      spictrl = (spi_ctrl*) SPI2_CTRL_ADDR;
      break;
    default:
      ux00boot_fail(ERROR_CODE_UNHANDLED_SPI_DEVICE, 0);
      break;
  }

  uint32_t error = 0;

  switch (boot_routine)
  {
    case UX00BOOT_ROUTINE_FLASH:
      error = initialize_spi_flash_direct(spictrl, peripheral_input_khz);
      if (!error) error = load_spiflash_gpt_partition(spictrl, dst, partition_type_guid);
      break;
    case UX00BOOT_ROUTINE_MMAP:
      error = initialize_spi_flash_mmap_single(spictrl, peripheral_input_khz);
      if (!error) error = load_mmap_gpt_partition(spimem, dst, partition_type_guid);
      break;
    case UX00BOOT_ROUTINE_MMAP_QUAD:
      error = initialize_spi_flash_mmap_quad(spictrl, peripheral_input_khz);
      if (!error) error = load_mmap_gpt_partition(spimem, dst, partition_type_guid);
      break;
    case UX00BOOT_ROUTINE_SDCARD:
    case UX00BOOT_ROUTINE_SDCARD_NO_INIT:
      {
        int32_t skip_sd_init_commands = (boot_routine == UX00BOOT_ROUTINE_SDCARD) ? 0 : 1;
        error = initialize_sd(spictrl, peripheral_input_khz, skip_sd_init_commands);
        if (!error) error = load_sd_gpt_partition(spictrl, dst, partition_type_guid);
      }
      break;
    default:
      error = ERROR_CODE_UNHANDLED_BOOT_ROUTINE;
      break;
  }

  if (error) {
    ux00boot_fail(error, 0);
  }

}
#endif /* _WITH_GPT_ */

/******************************************************************************/

/** End Of File */
