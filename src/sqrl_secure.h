/** @file sqrl_secure.h
 *
 * Secure utility functions for memory and string handling
 *
 * @author Security Audit Team
 *
 * This file is part of libsqrl. It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
 */

#ifndef SQRL_SECURE_H_INCLUDED
#define SQRL_SECURE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Securely copy a string with bounds checking
 *
 * Prevents buffer overflow by enforcing destination size limit.
 * Always null-terminates the destination string.
 *
 * @param dest Destination buffer
 * @param src Source string
 * @param dest_size Size of destination buffer
 * @return Number of characters copied (excluding null terminator), or -1 on error
 */
int sqrl_secure_strcpy(char *dest, const char *src, size_t dest_size);

/**
 * @brief Securely concatenate strings with bounds checking
 *
 * @param dest Destination buffer (must be null-terminated)
 * @param src Source string to append
 * @param dest_size Total size of destination buffer
 * @return Number of characters in final string, or -1 on error
 */
int sqrl_secure_strcat(char *dest, const char *src, size_t dest_size);

/**
 * @brief Securely clear and free a string
 *
 * Zeros memory before freeing to prevent sensitive data leakage.
 *
 * @param str Pointer to string pointer (set to NULL after freeing)
 * @param len Length of string (if known), or 0 to use strlen
 */
void sqrl_secure_free_string(char **str, size_t len);

/**
 * @brief Securely clear a buffer (platform-aware)
 *
 * Uses platform-specific methods to ensure the compiler doesn't
 * optimize away the memory clearing operation.
 *
 * @param buf Buffer to clear
 * @param len Length of buffer in bytes
 */
void sqrl_secure_memzero(void *buf, size_t len);

/**
 * @brief Securely allocate memory with automatic clearing on free
 *
 * Wrapper around sodium_malloc for consistency.
 *
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 */
void *sqrl_secure_malloc(size_t size);

/**
 * @brief Securely free memory with clearing
 *
 * Wrapper around sodium_free for consistency.
 *
 * @param ptr Pointer to memory to free
 */
void sqrl_secure_mfree(void *ptr);

/**
 * @brief Check if running in DEBUG mode at runtime
 *
 * Helps prevent accidental use of weakened crypto in production.
 *
 * @return true if compiled in DEBUG mode
 */
bool sqrl_is_debug_build(void);

/**
 * @brief Validate that security parameters meet minimum requirements
 *
 * @return true if security parameters are acceptable for production
 */
bool sqrl_security_check(void);

#ifdef __cplusplus
}
#endif

#endif /* SQRL_SECURE_H_INCLUDED */
