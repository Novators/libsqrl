/** \file rdrand.c
 *
 * \author John M. (Intel)
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/
#include <stdint.h>

/* From http://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide/ */

#include "rdrand.h"
#include <string.h>

#ifdef _WIN32
#define cpuid(in, out) __cpuid( out, in )
#else
#define cpuid(in, out) \
		asm("cpuid": "=a" (out[0]), \
					 "=b" (out[1]), \
					 "=c" (out[2]), \
					 "=d" (out[3]) : "a" (in))
#endif

static bool rdrand_avail = false;
static bool rdrand_tested = false;

static /*inline*/ int __rdrand64(uint64_t *val)
{
	uint64_t	tmp;
	int 		ret;
#ifdef _WIN32
	tmp = 0;
	ret = 1;
#else
    asm("rdrand %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;":"=r"(tmp),"=r"(ret)::"%rax","%rdx");
#endif
        *val = tmp;
	return ret;
}

void rdrand64(uint64_t *val)
{
        while (__rdrand64(val) == 0)
                ;
}

bool rdrand_available()
{
#ifdef _WIN32
	// Not implemented for Windows yet...
	return false;
#else
	if( !rdrand_tested ) {
		rdrand_avail = false;
		uint32_t tmp[4] = { -1 };
        cpuid( 0, tmp );
        if( !((memcmp( &tmp[1], "Genu", 4 ) == 0 ) &&
			(memcmp( &tmp[3], "ineI", 4 ) == 0 ) &&
            (memcmp( &tmp[2], "ntel", 4 ) == 0 ))) {
            //fprintf( stderr, "Not a recognized Intel CPU.\n" );
        } else {
            cpuid( 1, tmp );
            if( !( tmp[2] & 0x40000000 )) {
                //fprintf( stderr, "CPU does not support rdrand.\n" );
            } else {
                //fprintf( stderr, "CPU supports rdrand.\n" );
                rdrand_avail = true;
            }
        }
        rdrand_tested = true;
    }
    return rdrand_avail;
#endif
}
