/** \file SqrlBase64.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLBASE64_H
#define SQRLBASE64_H

#include "sqrl.h"
#include "SqrlEncoder.h"

class DLL_PUBLIC SqrlBase64 : SqrlEncoder
{
public:
	SQRL_STRING *encode( SQRL_STRING *dest, const SQRL_STRING *src, bool append = false );
	SQRL_STRING *decode( SQRL_STRING *dest, const SQRL_STRING *src, bool append = false );
};
#endif // SQRLBASE64_H
