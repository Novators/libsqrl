/** \file SqrlBase56Check.h
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLBASE56CHECK_H
#define SQRLBASE56CHECK_H

#include "sqrl.h"
#include "SqrlEncoder.h"
#include "SqrlBase56.h"

class DLL_PUBLIC SqrlBase56Check : SqrlBase56
{
public:

	SqrlString *encode( SqrlString *dest, const SqrlString *src, bool append = false );
	SqrlString *decode( SqrlString *dest, const SqrlString *src, bool append = false );
};
#endif // SQRLBASE56CHECK_H
