/** @file sqrl_secure.c
 *
 * Implementation of secure utility functions
 *
 * @author Security Audit Team
 *
 * This file is part of libsqrl. It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
 */

#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include "sqrl_secure.h"
#include "sqrl_expert.h"

int sqrl_secure_strcpy(char *dest, const char *src, size_t dest_size)
{
    if (!dest || !src || dest_size == 0) {
        return -1;
    }

    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dest_size - 1) ? src_len : dest_size - 1;

    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';

    return (int)copy_len;
}

int sqrl_secure_strcat(char *dest, const char *src, size_t dest_size)
{
    if (!dest || !src || dest_size == 0) {
        return -1;
    }

    size_t dest_len = strlen(dest);
    if (dest_len >= dest_size) {
        return -1;
    }

    size_t remaining = dest_size - dest_len - 1;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < remaining) ? src_len : remaining;

    memcpy(dest + dest_len, src, copy_len);
    dest[dest_len + copy_len] = '\0';

    return (int)(dest_len + copy_len);
}

void sqrl_secure_free_string(char **str, size_t len)
{
    if (!str || !*str) {
        return;
    }

    if (len == 0) {
        len = strlen(*str);
    }

    /* Clear the string before freeing */
    sodium_memzero(*str, len);
    free(*str);
    *str = NULL;
}

void sqrl_secure_memzero(void *buf, size_t len)
{
    if (!buf || len == 0) {
        return;
    }

    /* Use libsodium's secure memory zeroing */
    sodium_memzero(buf, len);
}

void *sqrl_secure_malloc(size_t size)
{
    if (size == 0) {
        return NULL;
    }

    return sodium_malloc(size);
}

void sqrl_secure_mfree(void *ptr)
{
    if (ptr) {
        sodium_free(ptr);
    }
}

bool sqrl_is_debug_build(void)
{
#ifdef DEBUG
    return true;
#else
    return false;
#endif
}

bool sqrl_security_check(void)
{
    bool secure = true;

#ifdef DEBUG
    /* Warn about debug build */
    secure = false;
#endif

    /* Check N-factor is reasonable */
    if (SQRL_DEFAULT_N_FACTOR < 9) {
        secure = false;
    }

    /* Check enscrypt seconds */
    if (SQRL_DEFAULT_ENSCRYPT_SECONDS < 5) {
        secure = false;
    }

    return secure;
}
