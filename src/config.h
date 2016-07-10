/** @file config.h

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/
#pragma once

#define SCRYPT_SALSA
#define SCRYPT_SHA256

#if defined WIN32 || defined CYGWIN
  #ifdef CMAKE_COMPILER_IS_GNUCC
    #define DLL_PUBLIC __attribute__ ((dllexport))
  #else
    #define DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
  #endif
  #define DLL_LOCAL
#else
  #define DLL_PUBLIC __attribute__ ((visibility ("default")))
  #define DLL_LOCAL  __attribute__ ((visibility ("hidden")))
#endif
