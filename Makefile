# Copyright 2019 SiFive, Inc #
# SPDX-License-Identifier: MIT #

PROGRAM ?= example-secure-bootrom

# ----------------------------------------------------------------------
# Common def
# ----------------------------------------------------------------------
override CURRENT_DIR := $(patsubst %/,%, $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))
override BUILD_DIRECTORY = $(CURRENT_DIR)/$(CONFIGURATION)build
override SOURCE_DIR = $(CURRENT_DIR)

# ----------------------------------------------------------------------
# Add custom flags for libscl 
# ----------------------------------------------------------------------
SCL_SOURCE_PATH ?= ../../scl-metal
SCL_DIR = $(abspath $(SCL_SOURCE_PATH))
include $(SCL_DIR)/scripts/scl.mk

TEST_FLAGS_SCL := $(foreach dir,$(SCL_INCLUDES),-I $(dir))
override CFLAGS += $(foreach dir,$(SCL_INCLUDES),-I $(dir))

override LDLIBS += -lscl
override LDFLAGS += -L$(join $(abspath  $(BUILD_DIRECTORY)),/scl/lib)


# ----------------------------------------------------------------------
# secure boot ROM 
# ----------------------------------------------------------------------
include $(CURRENT_DIR)/scripts/securebootrom.mk

CROSS_COMPILE ?= riscv64-unknown-elf

SCRIPT_SOURCE_PATH ?= ../../scripts
SCRIPT_DIR = $(abspath $(SCRIPT_SOURCE_PATH))


override API_SOURCES = $(foreach src_api,$(SRC_SBR_DIR),$(wildcard $(src_api)/*.c))
override ASM_SOURCES = $(foreach src_asm,$(SRC_SBR_DIR),$(wildcard $(src_asm)/*.S))

override OBJS += $(addprefix $(BUILD_DIRECTORY)/, $(notdir $(API_SOURCES:%.c=%.o)))
override OBJS += $(addprefix $(BUILD_DIRECTORY)/, $(notdir $(ASM_SOURCES:%.S=%.o)))

override CFLAGS += $(__CLIST_DEFINITIONS)
override CFLAGS += $(__CLIST_UNDEFINITIONS)

override CFLAGS += $(foreach dir,$(INC_SBR_DIR),-I $(dir))

override ASFLAGS += $(__ALIST_DEFINITIONS)
override ASFLAGS += $(__ALIST_UNDEFINITIONS)

override LDFLAGS  += -Wl,--defsym,__stack_size=0x2000

# ----------------------------------------------------------------------
# Add variable for HCA
# ----------------------------------------------------------------------
export HCA_VERSION ?= 0.5

# ----------------------------------------------------------------------
# Update LDLIBS
# ----------------------------------------------------------------------
FILTER_PATTERN = -Wl,--end-group
override LDLIBS := $(filter-out $(FILTER_PATTERN),$(LDLIBS)) -Wl,--end-group

# ----------------------------------------------------------------------
# Macro
# ----------------------------------------------------------------------
ifeq ($(VERBOSE),TRUE)
	HIDE := 
else
	HIDE := @
endif

# ----------------------------------------------------------------------
# Build rules
# ----------------------------------------------------------------------
$(BUILD_DIRECTORY)/%.o: $(API_SOURCES)
	$(HIDE) mkdir -p $(dir $@)
	$(HIDE) $(CC) -c -o $@ $(CFLAGS) $(XCFLAGS) $(filter %/$(notdir $(@:.o=.c)),$(API_SOURCES))

#$(BUILD_DIRECTORY)/%.o: $(ASM_SOURCES)
#	$(HIDE) mkdir -p $(dir $@)
#	$(HIDE) $(CC) -c -o $@ $(ASFLAGS) $(filter %/$(notdir $(@:.o=.S)),$(ASM_SOURCES))

$(BUILD_DIRECTORY)/scl/lib/libscl.a: 
	make -f Makefile -C $(SCL_DIR) \
	BUILD_DIR=$(join $(abspath  $(BUILD_DIRECTORY)),/scl) \
	libscl.a \
	VERBOSE=$(VERBOSE)

$(PROGRAM): \
	$(BUILD_DIRECTORY)/scl/lib/libscl.a \
	$(OBJS)
	$(CC) $(CFLAGS) $(XCFLAGS) $(LDFLAGS) $(OBJS) $(LDLIBS) -o $@
	@echo
	@cp $(PROGRAM) $(PROGRAM)_ori.elf
	$(CROSS_COMPILE)-objcopy @$(CURRENT_DIR)/scripts/SectionsToRemove.mk $@ $@
	@echo

clean::
	rm -rf $(BUILD_DIRECTORY)
	rm -f $(PROGRAM) $(PROGRAM).hex
