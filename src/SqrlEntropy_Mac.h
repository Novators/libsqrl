/** \file SqrlEntropy_Mac.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/time.h>

namespace libsqrl
{
    struct sqrl_fast_flux_entropy
    {
        uint64_t mat;
        struct timeval realtime;
        struct rusage rusage;
        uint32_t rdtsclow;
        uint32_t rdtschigh;
    };

    struct sqrl_entropy_bracket_block
    {
        uint8_t seed[crypto_hash_sha512_BYTES];
        uint8_t random[crypto_hash_sha512_BYTES];
        struct sqrl_fast_flux_entropy ffe;
        pid_t processId;
        pid_t threadId;
        uint64_t rdrand[32];
    };

    static void sqrl_store_fast_flux_entropy( struct sqrl_fast_flux_entropy* ffe ) {
        ffe->mat = mach_absolute_time();
        gettimeofday( &ffe->realtime, NULL );
        getrusage( RUSAGE_SELF, &ffe->rusage );
        asm volatile("rdtsc" : "=a" (ffe->rdtsclow), "=d" (ffe->rdtschigh));
    }


    static void sqrl_add_entropy_bracket( struct sqrl_entropy_pool* pool, uint8_t* seed ) {
        int i;
        struct sqrl_entropy_bracket_block bracket;
        memset( &bracket, 0, sizeof( struct sqrl_entropy_bracket_block ) );
        sqrl_store_fast_flux_entropy( &bracket.ffe );
        if( seed ) {
            memcpy( &bracket.seed, seed, crypto_hash_sha512_BYTES );
        }
        sqrl_randombytes( &bracket.random, crypto_hash_sha512_BYTES );
        if( rdrand_available() ) {
            for( i = 0; i < 32; i++ ) {
                rdrand64( &bracket.rdrand[i] );
            }
        } else {
            sqrl_randombytes( &bracket.rdrand, 256 );
        }
        bracket.processId = getpid();
        bracket.threadId = syscall( SYS_gettid );
        crypto_hash_sha512_update( &pool->state, (unsigned char*)(&bracket), sizeof( struct sqrl_entropy_bracket_block ) );
    }
}