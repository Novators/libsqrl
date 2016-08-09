/** \file SqrlEntropy_Linux.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>

namespace libsqrl
{
    struct sqrl_fast_flux_entropy
    {
        struct timespec monotime;
        struct timespec realtime;
        struct rusage rusage;
#ifdef RUSAGE_THREAD
        struct rusage tusage;
#endif
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
        clock_gettime( CLOCK_MONOTONIC, &ffe->monotime );
        clock_gettime( CLOCK_REALTIME, &ffe->realtime );
        getrusage( RUSAGE_SELF, &ffe->rusage );
#ifdef RUSAGE_THREAD
        getrusage( RUSAGE_THREAD, &ffe->tusage );
#endif
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