/** @file secure_test.c
 *
 * Test suite for secure memory handling functions
 *
 * This file is part of libsqrl. It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../sqrl_secure.h"

static int test_count = 0;
static int pass_count = 0;
static int fail_count = 0;

#define TEST(name) printf("TEST: %s\n", name); test_count++
#define PASS() printf("  PASS\n"); pass_count++
#define FAIL(msg) printf("  FAIL: %s\n", msg); fail_count++

void test_secure_strcpy(void)
{
    TEST("sqrl_secure_strcpy - normal copy");
    {
        char dest[32];
        const char *src = "Hello, World!";
        int result = sqrl_secure_strcpy(dest, src, sizeof(dest));
        if (result == (int)strlen(src) && strcmp(dest, src) == 0) {
            PASS();
        } else {
            FAIL("Copy did not match expected");
        }
    }

    TEST("sqrl_secure_strcpy - truncation");
    {
        char dest[8];
        const char *src = "Hello, World!";
        int result = sqrl_secure_strcpy(dest, src, sizeof(dest));
        if (result == 7 && strcmp(dest, "Hello, ") == 0) {
            PASS();
        } else {
            FAIL("Truncation did not work correctly");
        }
    }

    TEST("sqrl_secure_strcpy - null parameters");
    {
        char dest[32];
        int result = sqrl_secure_strcpy(NULL, "test", sizeof(dest));
        if (result == -1) {
            result = sqrl_secure_strcpy(dest, NULL, sizeof(dest));
            if (result == -1) {
                PASS();
            } else {
                FAIL("Should return -1 for NULL src");
            }
        } else {
            FAIL("Should return -1 for NULL dest");
        }
    }

    TEST("sqrl_secure_strcpy - zero size");
    {
        char dest[32];
        int result = sqrl_secure_strcpy(dest, "test", 0);
        if (result == -1) {
            PASS();
        } else {
            FAIL("Should return -1 for zero size");
        }
    }
}

void test_secure_strcat(void)
{
    TEST("sqrl_secure_strcat - normal concatenation");
    {
        char dest[32] = "Hello, ";
        const char *src = "World!";
        int result = sqrl_secure_strcat(dest, src, sizeof(dest));
        if (result == 13 && strcmp(dest, "Hello, World!") == 0) {
            PASS();
        } else {
            FAIL("Concatenation did not match expected");
        }
    }

    TEST("sqrl_secure_strcat - truncation");
    {
        char dest[12] = "Hello, ";
        const char *src = "World!";
        int result = sqrl_secure_strcat(dest, src, sizeof(dest));
        if (result == 11 && strcmp(dest, "Hello, Worl") == 0) {
            PASS();
        } else {
            FAIL("Truncation did not work correctly");
        }
    }
}

void test_secure_free_string(void)
{
    TEST("sqrl_secure_free_string - clears and frees");
    {
        char *str = malloc(16);
        strcpy(str, "SENSITIVE_DATA");
        sqrl_secure_free_string(&str, 0);
        if (str == NULL) {
            PASS();
        } else {
            FAIL("Pointer should be set to NULL");
        }
    }

    TEST("sqrl_secure_free_string - handles NULL");
    {
        char *str = NULL;
        sqrl_secure_free_string(&str, 0);
        if (str == NULL) {
            PASS();
        } else {
            FAIL("Should handle NULL gracefully");
        }
    }
}

void test_secure_memzero(void)
{
    TEST("sqrl_secure_memzero - clears buffer");
    {
        uint8_t buf[32];
        memset(buf, 0xFF, sizeof(buf));
        sqrl_secure_memzero(buf, sizeof(buf));

        int all_zero = 1;
        for (size_t i = 0; i < sizeof(buf); i++) {
            if (buf[i] != 0) {
                all_zero = 0;
                break;
            }
        }

        if (all_zero) {
            PASS();
        } else {
            FAIL("Buffer was not completely zeroed");
        }
    }

    TEST("sqrl_secure_memzero - handles NULL");
    {
        sqrl_secure_memzero(NULL, 32);
        PASS();
    }

    TEST("sqrl_secure_memzero - handles zero length");
    {
        uint8_t buf[32];
        memset(buf, 0xFF, sizeof(buf));
        sqrl_secure_memzero(buf, 0);
        if (buf[0] == 0xFF) {
            PASS();
        } else {
            FAIL("Should not modify buffer with zero length");
        }
    }
}

void test_security_checks(void)
{
    TEST("sqrl_is_debug_build - returns correct value");
    {
#ifdef DEBUG
        if (sqrl_is_debug_build()) {
            PASS();
        } else {
            FAIL("Should return true in DEBUG build");
        }
#else
        if (!sqrl_is_debug_build()) {
            PASS();
        } else {
            FAIL("Should return false in Release build");
        }
#endif
    }

    TEST("sqrl_security_check - validates parameters");
    {
        bool result = sqrl_security_check();
#ifdef DEBUG
        if (!result) {
            PASS();
        } else {
            FAIL("DEBUG builds should fail security check");
        }
#else
        printf("  Security check returned: %s\n", result ? "PASS" : "FAIL");
        PASS();
#endif
    }
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("=== libsqrl Secure Memory Test Suite ===\n\n");

    if (sodium_init() < 0) {
        printf("ERROR: Could not initialize libsodium\n");
        return 1;
    }

    test_secure_strcpy();
    test_secure_strcat();
    test_secure_free_string();
    test_secure_memzero();
    test_security_checks();

    printf("\n=== Test Results ===\n");
    printf("Total:  %d\n", test_count);
    printf("Passed: %d\n", pass_count);
    printf("Failed: %d\n", fail_count);

    if (fail_count > 0) {
        return 1;
    }

    return 0;
}
