# libsqrl Security Audit Report

**Version:** 18.04.0007
**Date:** 2025-11-16
**Auditor:** Automated Security Analysis

## Executive Summary

This document provides a comprehensive security audit of the libsqrl SQRL authentication library, identifying critical vulnerabilities, dependency issues, and recommended remediation steps.

---

## 1. Project Requirements

### Core Functionality
- SQRL (Secure Quick Reliable Login) client and server authentication
- Identity management with encrypted storage (S4 format)
- Cryptographic operations: Ed25519 signatures, AES-GCM encryption, HMAC-SHA256
- Key derivation via EnScrypt (Scrypt-based)
- Multi-platform support (Linux, macOS, Windows)

### Technical Requirements
- Build System: CMake 2.8+ (current) → **Should be 3.10+**
- C Standard: C99/C11
- Threading: POSIX threads (pthread)
- Memory Protection: Page-level protection via libsodium

---

## 2. Dependencies and Upgrade Paths

### Primary Dependencies

| Dependency | Current Version | Latest Stable (Nov 2025) | Upgrade Path | Priority |
|------------|----------------|---------------------------|--------------|----------|
| **libsodium** | `stable` branch (unpinned) | **1.0.20** | Pin to 1.0.20 | CRITICAL |
| **CMake** | 2.8 minimum | **3.10+** recommended (4.1.1 latest) | Update to 3.10+ | HIGH |
| **pthread** | System library | N/A | N/A | - |
| **librt** | System library | N/A | N/A | - |
| **libm** | System library | N/A | N/A | - |

### Internal Dependencies (Bundled)

| Component | Source | Version | Status |
|-----------|--------|---------|--------|
| AES-128/192/256 | GRC.com (Public Domain) | Unknown | Audit needed |
| AES-GCM | GRC.com (Public Domain) | Unknown | Audit needed |
| UT_string | BSD License | Unknown | OK |
| Base56/Base64url | Internal | - | OK |

### Upgrade Instructions

**libsodium 1.0.20** (from stable branch):
```cmake
# Change in CMakeLists.txt line 76
GIT_TAG 1.0.20  # was: stable
```

Key changes in 1.0.20:
- Fixed compilation issues
- Better ARM64 support (MSVC)
- 16K page size support for Android
- Zig 0.14+ compatibility
- -O3 optimization instead of -Ofast

**CMake 3.10+**:
```cmake
# Change line 3
cmake_minimum_required(VERSION 3.10)  # was: 2.8
```

---

## 3. Security Vulnerabilities Identified

### CRITICAL - CWE-226: Sensitive Information Not Cleared

#### Finding 1: Temporary Key Buffers Not Cleared
**File:** `src/crypto/crypt.c`
**Lines:** 31, 104
**Severity:** HIGH
**Description:** Temporary arrays containing derived cryptographic keys are not zeroed after use.

```c
// Line 31 in sqrl_enscrypt()
uint8_t t[2][32] = {{0},{0}};  // Contains key material
// ... function ends without clearing t[]
```

**Impact:** Sensitive key material remains in stack memory, potentially recoverable through memory dumps or cold boot attacks.

#### Finding 2: Site Keys Not Cleared on Error Paths
**File:** `src/client_protocol.c`
**Lines:** 387-399
**Severity:** HIGH
**Description:** `sqrl_site_create_unlock_keys()` creates temporary RLK (Random Lock Key) that is not properly cleared.

```c
void sqrl_site_create_unlock_keys( struct Sqrl_Site *site ) {
    uint8_t scratch[64];
    uint8_t rlk[SQRL_KEY_SIZE];  // NOT CLEARED
    sqrl_gen_rlk( rlk );
    // ... rlk never cleared before function returns
}
```

#### Finding 3: Signature Buffer Not Cleared
**File:** `src/client_protocol.c`
**Lines:** 574
**Severity:** MEDIUM
**Description:** Binary signature buffer not cleared after use.

```c
UT_string *sqrl_site_client_body( Sqrl_Site *site ) {
    uint8_t binSig[64];  // Contains signatures - NOT CLEARED
    // ...
    return result;
}
```

### CRITICAL - CWE-119: Buffer Overflow via strcpy()

#### Finding 4: Unsafe strcpy() Operations
**Files:** Multiple
**Severity:** CRITICAL
**Description:** Using strcpy() without bounds checking allows buffer overflows.

Affected locations:
- `src/client_protocol.c:187-188` - Challenge/URL copy
- `src/client_protocol.c:221` - SIN value copy
- `src/server.c:254,256,269,272,285,286` - Server blob operations
- `src/server_protocol.c:337` - SUK key copy
- `src/uri.c:98,154,156,312,322,340,351` - URI parsing
- `src/storage.c:482` - Unique ID copy

**Impact:** Remote code execution, denial of service, memory corruption.

### HIGH - CWE-200: Exposure of Sensitive Information

#### Finding 5: Sensitive Strings Freed Without Clearing
**File:** `src/transaction.c`
**Lines:** 96-97
**Severity:** HIGH
**Description:** Transaction strings potentially containing authentication tokens are freed without clearing.

```c
if( freeMe->string ) free( freeMe->string );
if( freeMe->altIdentity ) free( freeMe->altIdentity );
```

**Impact:** Sensitive authentication data may remain in heap memory.

### MEDIUM - Weakened Cryptography in DEBUG Mode

**File:** `src/sqrl_client.h`
**Lines:** 28-39
**Severity:** HIGH (when DEBUG enabled)

```c
#ifdef DEBUG
#define SQRL_RESCUE_ENSCRYPT_SECONDS 5    // Normal: 60
#define SQRL_DEFAULT_ENSCRYPT_SECONDS 1   // Normal: 5
#define SQRL_DEFAULT_N_FACTOR 1           // Normal: 9 (should be 14+)
#endif
```

**Impact:** Passwords become trivially bruteforce-able in DEBUG builds.

### LOW - Other Issues

1. **CMakeLists.txt:39** - Debug build by default
2. **sqrl_expert.h:20** - Weak N-factor (9 vs recommended 14+)
3. Missing compiler hardening flags (-fstack-protector-strong, RELRO, PIE)

---

## 4. Remediation Plan

### Priority 1: Critical Security Fixes

1. **Replace all strcpy() with secure alternatives**
   - Use `strncpy()` or custom `sqrl_secure_strcpy()`
   - Add length validation

2. **Implement secure memory clearing throughout**
   - Clear all temporary key buffers with `sodium_memzero()`
   - Clear signature buffers after use
   - Clear authentication strings before freeing

3. **Change build configuration to Release**
   ```cmake
   set(CMAKE_BUILD_TYPE Release)
   ```

### Priority 2: Dependency Updates

1. **Pin libsodium to 1.0.20**
   ```cmake
   GIT_TAG 1.0.20
   ```

2. **Update CMake minimum to 3.10**
   ```cmake
   cmake_minimum_required(VERSION 3.10)
   ```

3. **Add compiler hardening flags**
   ```cmake
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fstack-protector-strong")
   if(NOT WIN32)
       set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now")
   endif()
   ```

### Priority 3: Test Coverage & CI/CD

1. Add security-focused test cases
2. Implement GitHub Actions CI/CD pipeline
3. Add memory sanitizer testing (ASan, MSan)
4. Add static analysis (cppcheck, clang-tidy)

---

## 5. Files to be Modified

### Core Security Fixes
- `src/crypto/crypt.c` - Add secure memory clearing
- `src/client_protocol.c` - Fix strcpy, clear sensitive buffers
- `src/server_protocol.c` - Fix strcpy, clear sensitive buffers
- `src/server.c` - Fix strcpy operations
- `src/uri.c` - Fix strcpy operations
- `src/storage.c` - Fix strcpy operation
- `src/transaction.c` - Clear sensitive data before freeing
- `src/client.c` - Clear altIdentity properly
- `src/sqrl_internal.h` - Add secure string functions

### Build System Updates
- `CMakeLists.txt` - Update dependencies, hardening flags

### New Files
- `.github/workflows/ci.yml` - CI/CD pipeline
- `src/sqrl_secure.h` - Secure utility functions
- `src/sqrl_secure.c` - Implementation

---

## 6. Test Coverage Requirements

### Existing Tests (9 test suites)
- `encdec_test` - Encoding/decoding
- `gcm_test` - AES-GCM cryptography
- `crypto_test` - General cryptography
- `uri_test` - URI parsing
- `storage_test` - S4 storage
- `user_test` - User management
- `client_test` - Client protocol
- `server_test` - Server operations
- `protocol_test` - Integration tests

### Required Additional Tests
1. **Secure memory clearing verification**
2. **Buffer overflow boundary testing**
3. **Memory sanitizer integration**
4. **Fuzzing for protocol parsing**

---

## 7. Compliance Notes

### OWASP Top 10 (2021)
- **A03: Injection** - Buffer overflow vulnerabilities (CRITICAL)
- **A02: Cryptographic Failures** - Weak key derivation in debug mode
- **A04: Insecure Design** - Sensitive data not cleared

### CWE Categories Addressed
- **CWE-119**: Improper Restriction of Operations within Memory Buffer
- **CWE-200**: Exposure of Sensitive Information
- **CWE-226**: Sensitive Information in Resource Not Removed Before Reuse
- **CWE-327**: Use of Broken or Risky Cryptographic Algorithm (DEBUG mode)

---

## 8. Timeline

| Phase | Task | Duration |
|-------|------|----------|
| 1 | Implement secure memory clearing functions | 1 hour |
| 2 | Fix all strcpy vulnerabilities | 2 hours |
| 3 | Update dependencies and build system | 1 hour |
| 4 | Add CI/CD pipeline | 1 hour |
| 5 | Enhance test coverage | 2 hours |
| 6 | Final validation and documentation | 1 hour |

**Total Estimated Time:** 8 hours

---

## 9. Recommendations

1. **IMMEDIATE**: Do not use DEBUG builds in production
2. **SHORT-TERM**: Apply all security patches in this audit
3. **MEDIUM-TERM**: Increase N-factor to 14+ for production
4. **LONG-TERM**: Consider migration to memory-safe language for critical paths

---

*End of Security Audit Report*
