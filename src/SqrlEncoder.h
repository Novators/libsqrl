/** \file SqrlEncoder.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLENCODER_H
#define SQRLENCODER_H

#include "sqrl.h"

class DLL_PUBLIC SqrlEncoder
{
public:
	virtual SQRL_STRING *encode( SQRL_STRING *dest, const SQRL_STRING *src, bool append = false ) = 0;
	virtual SQRL_STRING *decode( SQRL_STRING *dest, const SQRL_STRING *src, bool append = false ) = 0;
};
#endif // SQRLENCODER_H
