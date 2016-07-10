/** @file entropy.h 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef void* sqrl_entropy_pool;

sqrl_entropy_pool sqrl_entropy_create();
void sqrl_entropy_destroy(sqrl_entropy_pool);

//void sqrl_entropy_update( sqrl_entropy_pool );
void sqrl_entropy_add(sqrl_entropy_pool, uint8_t*, size_t);

int sqrl_entropy_estimate(sqrl_entropy_pool);
int sqrl_entropy_get(sqrl_entropy_pool, uint8_t*, int);
