/**
 * @file test_example.c
 * @brief test example
 * 
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 * 
 */

#include "unity.h"
#include "unity_fixture.h"

#include <string.h>

#include <metal/machine/platform.h>

#include <errors.h>
#include <ppm.h>


TEST_GROUP(ppm);

TEST_GROUP_RUNNER(ppm)
{
    RUN_TEST_CASE(ppm, shutdown_success);
}

TEST_SETUP(ppm) {}

TEST_TEAR_DOWN(ppm) {}

TEST(ppm, shutdown_success)
{
    int result = 0;

    result = ppm_shutdown(NULL);

    TEST_ASSERT_TRUE(NO_ERROR == result);
}
