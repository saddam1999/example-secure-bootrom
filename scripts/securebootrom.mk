# Copyright 2020 SiFive, Inc #
# SPDX-License-Identifier: MIT #

## All compilation flags and options for SecureBoot ROM
include $(CURRENT_DIR)/scripts/defines.mk

## List of source/include folders

override SRC_SBR_PATH = $(CURRENT_DIR)
override INC_SBR_PATH = $(CURRENT_DIR)/include

override SRC_SBR_DIR = $(SRC_SBR_PATH)
override SRC_SBR_DIR += $(SRC_SBR_PATH)/api/daim
override SRC_SBR_DIR += $(SRC_SBR_PATH)/api/km
override SRC_SBR_DIR += $(SRC_SBR_PATH)/api/pi
override SRC_SBR_DIR += $(SRC_SBR_PATH)/api/ppm
override SRC_SBR_DIR += $(SRC_SBR_PATH)/api/sbrm
override SRC_SBR_DIR += $(SRC_SBR_PATH)/api/slbv
override SRC_SBR_DIR += $(SRC_SBR_PATH)/api/sp

override INC_SBR_DIR = $(INC_SBR_PATH)
override INC_SBR_DIR += $(INC_SBR_PATH)/api/daim
override INC_SBR_DIR += $(INC_SBR_PATH)/api/km
override INC_SBR_DIR += $(INC_SBR_PATH)/api/pi
override INC_SBR_DIR += $(INC_SBR_PATH)/api/ppm
override INC_SBR_DIR += $(INC_SBR_PATH)/api/sbrm
override INC_SBR_DIR += $(INC_SBR_PATH)/api/slbv
override INC_SBR_DIR += $(INC_SBR_PATH)/api/sp

## End Of File
