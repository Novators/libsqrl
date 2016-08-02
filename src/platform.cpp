/** @file platform.cpp

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "sqrl.h"

#ifdef _WIN32
#include <Windows.h>
#endif

void sqrl_sleep(int sleepMs)
{
#ifdef UNIX
    usleep(sleepMs * 1000);   // usleep takes sleep time in us (1 millionth of a second)
#endif
#ifdef _WIN32
    Sleep(sleepMs);
#endif
}

