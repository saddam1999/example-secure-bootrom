# Copyright 2020 SiFive, Inc #
# SPDX-License-Identifier: Apache-2.0 #

PROGRAM ?= example-secure-bootrom

# ----------------------------------------------------------------------
# Common def
# ----------------------------------------------------------------------
override CURRENT_DIR := $(patsubst %/,%, $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))
BUILD_DIRECTORY ?= $(abspath $(CURRENT_DIR)/$(CONFIGURATION)/build)
override SOURCE_DIR = $(CURRENT_DIR)/src

override SOURCE_DIRS := $(SOURCE_DIR)

override C_SOURCES = $(foreach dir,$(SOURCE_DIRS),$(wildcard $(dir)/*.c))
					
override ASM_SOURCES = $(wildcard *.S)
override OBJS :=	$(subst $(SOURCE_DIR),$(BUILD_DIRECTORY),$(C_SOURCES:.c=.o)) \
					$(subst $(SOURCE_DIR),$(BUILD_DIRECTORY),$(ASM_SOURCES:.S=.o))

# ----------------------------------------------------------------------
# Add custom flags for test
# ----------------------------------------------------------------------
TEST_FW_METAL_DIR = $(abspath $(CURRENT_DIR)/framework)
BUILD_DIRECTORY_TEST_FW = $(join $(abspath  $(BUILD_DIRECTORY)),/test/framework/Unity)

# Unity
UNITY_DIR = $(join $(TEST_FW_METAL_DIR),/Unity)
BUILD_DIRECTORY_UNITY = $(join $(BUILD_DIRECTORY_TEST_FW),/Unity)

UNITY_INCLUDES = 	$(UNITY_DIR)/src \
					$(UNITY_DIR)/extras/fixture/src

override UNITY_SOURCE_DIRS = 	$(UNITY_DIR)/src \
								$(UNITY_DIR)/extras/fixture/src

override UNITY_C_SOURCES = $(foreach dir,$(UNITY_SOURCE_DIRS),$(wildcard $(dir)/*.c))

override OBJS += $(subst $(UNITY_DIR),$(BUILD_DIRECTORY_UNITY),$(UNITY_C_SOURCES:.c=.o))

override CFLAGS += $(foreach dir,$(UNITY_INCLUDES),-I $(dir))
override CFLAGS += -DUNITY_FIXTURE_NO_EXTRAS

# ----------------------------------------------------------------------
# Common def
# ----------------------------------------------------------------------
override INCLUDE_DIRS := 	$(CURRENT_DIR)/include

# override CFLAGS += $(foreach dir,$(INCLUDES_DIR_BOOTROM),-I $(dir))

override CFLAGS += $(foreach dir,$(INCLUDE_DIRS),-I $(dir))
override CFLAGS += -Wall -Wextra -fstack-protector-all

override CFLAGS += -Wpedantic -Wcast-qual \
					-Wunreachable-code -Wstrict-aliasing -Wdangling-else \
					-Wconversion -Wsign-conversion -Wmissing-include-dirs \
					-Wduplicated-branches -Wduplicated-cond -Warray-bounds 

LIBSCL_METAL_CFLAGS += -fstack-protector-all

# # override CFLAGS += -I $(CURRENT_DIR)
# override ASFLAGS = $(CFLAGS)

# override LDFLAGS  += -Wl,--defsym,__stack_size=0x2000

# Gnerate .map out of source
DOT_MAP_FILTER_PATTERN = -Wl,-Map,$(PROGRAM).map
override LDFLAGS := $(filter-out $(DOT_MAP_FILTER_PATTERN),$(LDFLAGS)) -Wl,-Map,$(BUILD_DIRECTORY)/$(PROGRAM)-test.map

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

$(BUILD_DIRECTORY_UNITY)/%.o: $(UNITY_DIR)/%.c
	$(HIDE) mkdir -p $(dir $@)
	$(HIDE) $(CC) -c -o $@ $(CFLAGS) $(XCFLAGS) $<
	
$(BUILD_DIRECTORY)/%.o: $(SOURCE_DIR)/%.c
	$(HIDE) mkdir -p $(dir $@)
	$(HIDE) $(CC) -c -o $@ $(CFLAGS) $(XCFLAGS) $<

$(BUILD_DIRECTORY)/%.o: $(SOURCE_DIR)/%.S
	$(HIDE) mkdir -p $(dir $@)
	$(HIDE) $(CC) -c -o $@ $(ASFLAGS) $<

tests: \
	$(OBJS) \
	$(OBJS_BOOTROM)
	$(CC) $(CFLAGS) $(XCFLAGS) $(LDFLAGS) $(OBJS) $(OBJS_BOOTROM) $(LDLIBS) -o $(BUILD_DIRECTORY)/$(PROGRAM)-test

clean:
	rm -f $(PROGRAM) $(PROGRAM).hex
