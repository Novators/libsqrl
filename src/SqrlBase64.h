/** @file SqrlBase64.h
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLBASE64_H
#define SQRLBASE64_H

#include "sqrl.h"
#include "SqrlEncoder.h"

class DLL_PUBLIC SqrlBase64 : SqrlEncoder
{
public:
	std::string *encode( std::string *dest, const std::string *src, bool append = false );
	std::string *decode( std::string *dest, const std::string *src, bool append = false );
private:
	bool nextValue( uint32_t *nextValue, std::string::const_iterator &it, std::string::const_iterator &end );
};
#endif // SQRLBASE64_H
