/** @file SqrlUrlEncode.h
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLURLENCODE_H
#define SQRLURLENCODE_H

#include "sqrl.h"
#include "SqrlEncoder.h"

class DLL_PUBLIC SqrlUrlEncode : SqrlEncoder
{
public:
	std::string *encode( std::string *dest, const uint8_t *src, size_t src_len, bool append = false );
	std::string *decode( std::string *dest, const char *src, size_t src_len, bool append = false );
};
#endif // SQRLURLENCODE_H
