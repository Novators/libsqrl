/** \file SqrlEntropy_Win.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLENTROPY_WIN_H
#define SQRLENTROPY_WIN_H

#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

namespace libsqrl
{
    struct sqrl_fast_flux_entropy
    {
        LARGE_INTEGER performanceCounter;
        FILETIME filetime;
        FILETIME userModeTime;
        FILETIME kernelModeTime;
        FILETIME idleTime;
        unsigned __int64 rdtsc;
        MEMORYSTATUSEX memstat;
        FILETIME threadUser;
        FILETIME threadKernel;
        FILETIME threadExit;
        FILETIME threadCreate;
        FILETIME procUser;
        FILETIME procKernel;
        FILETIME procExit;
        FILETIME procCreate;
        SIZE_T maxWorkingSet;
        SIZE_T minWorkingSet;
    };

    struct sqrl_entropy_bracket_block
    {
        uint8_t seed[crypto_hash_sha512_BYTES];
        uint8_t random[crypto_hash_sha512_BYTES];
        struct sqrl_fast_flux_entropy ffe;
        DWORD processID;
        DWORD threadID;
        HWND desktopWindow;
        HWINSTA winsta;
        POINT curPos;
        uint64_t rdrand[32];
    };

    void sqrl_store_fast_flux_entropy( struct sqrl_fast_flux_entropy* ffe ) {
        QueryPerformanceCounter( &ffe->performanceCounter );
        GetSystemTimeAsFileTime( &ffe->filetime );
        GetSystemTimes( &ffe->idleTime, &ffe->kernelModeTime, &ffe->userModeTime );
        ffe->rdtsc = __rdtsc();
        GlobalMemoryStatusEx( &ffe->memstat );
        GetThreadTimes( GetCurrentThread(), &ffe->threadCreate, &ffe->threadExit, &ffe->threadKernel, &ffe->threadUser );
        GetProcessTimes( GetCurrentProcess(), &ffe->procCreate, &ffe->procExit, &ffe->procKernel, &ffe->procUser );
        GetProcessWorkingSetSize( GetCurrentProcess(), &ffe->minWorkingSet, &ffe->maxWorkingSet );
    }


    void SqrlEntropy::addBracket( uint8_t* seed ) {
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
        bracket.processID = GetCurrentProcessId();
        bracket.threadID = GetCurrentThreadId();
        bracket.desktopWindow = GetDesktopWindow();
        bracket.winsta = GetProcessWindowStation();
        GetCursorPos( &bracket.curPos );
        crypto_hash_sha512_update( (crypto_hash_sha512_state *)SqrlEntropy::state, (unsigned char*)(&bracket), sizeof( struct sqrl_entropy_bracket_block ) );
    }
}
#endif // SQRLENTROPY_WIN_H
