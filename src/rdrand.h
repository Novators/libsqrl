/** @file rdrand.h 

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
#pragma once

#include <stdint.h>
#include <stdbool.h>

void rdrand16(uint16_t *val);
void rdrand32(uint32_t *val);
void rdrand64(uint64_t *val);
bool rdrand_available(void);
