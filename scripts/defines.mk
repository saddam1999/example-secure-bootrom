# Copyright 2020 SiFive, Inc #
# SPDX-License-Identifier: MIT #

## Versions of SecureBoot ROM and "reference base" versioin of SecureBoot ROM
include $(CURRENT_DIR)/scripts/version.mk

## List of constants to be activated/defined
## C code
__CLIST_DEFINITIONS = -D_FPGA_SPECIFIC_ \
						-D_WITH_GPIO_CHARAC_ \
						-D_WITH_TEST_PSK_ \
						-D_WITH_TEST_CUK_ \
						-D_WITH_TEST_CSK_ \
						-D_WITH_FREEDOM_METAL_ \
						-D_WITH_FIRMWARE_VERSION_ \
						-D_SUPPORT_ALGO_ECDSA384_ \
						-D_SUP_OLD_BEHAVIOR_ \
						-D_WITH_UART_WORKAROUND_\
						-D_TEST_KEYS_ \
						-D_WITHOUT_SELFTESTS_ \
						-D_LIFE_CYCLE_PHASE1_ \
						-DCOREIP_MEM_WIDTH=$(COREIP_MEM_WIDTH) \
						-DMAJOR_VERSION=$(__MAJOR_VERSION) \
						-DMINOR_VERSION=$(__MINOR_VERSION) \
						-DEDIT_VERSION=$(__EDIT_VERSION) \
						-DREF_MAJOR_VERSION=$(__BREF_MAJOR_VERSION) \
						-DREF_MINOR_VERSION=$(__BREF_MINOR_VERSION) \
						-DREF_EDIT_VERSION=$(__BREF_EDIT_VERSION)
				
## Assembly code
__ALIST_DEFINITIONS =

## List of constants to be deactivated/undefined
## C code
__CLIST_UNDEFINITIONS = -USCL_WORD32 \
						-U_WITH_QEMU_ \
						-U_WITH_PATCH_MGNT_ \
						-U_LIFE_CYCLE_PHASE2_ \
						-U_WITH_RMA_MODE_ON_ \
						-U_WITH_CHECK_ROM_ \
						-U_WITH_128BITS_ADDRESSING_ \
						-U_WITH_BOOT_ADDR_ \
						-U_DBG_DEVEL_ \
						-U_DBG_BEACON_
## Assembly code
__ALIST_UNDEFINITIONS =

## End Of File
