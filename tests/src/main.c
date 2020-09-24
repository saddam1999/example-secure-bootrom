/**
 * @file test-scl-metal.c
 * @brief Main of the scl-metal tests
 * @details This run all test group
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity_fixture.h"

#include <stdint.h>
#include <stdlib.h>

#if UINT32_MAX == UINTPTR_MAX
#define STACK_CHK_GUARD 0xe2dee396
#else
#define STACK_CHK_GUARD 0x595e9fbd94fda766
#endif

uintptr_t __stack_chk_guard = STACK_CHK_GUARD;

void __stack_chk_fail(void) { TEST_FAIL_MESSAGE("Stack smashing detected"); }

static void RunAllTests(void)
{
    UnityFixture.Verbose = 1;
    
    RUN_TEST_GROUP(ppm);
}

int main(int argc, const char *argv[])
{
    return UnityMain(argc, argv, RunAllTests);
}
