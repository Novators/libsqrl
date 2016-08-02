/** @file SqrlEncoder.h
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLENCODER_H
#define SQRLENCODER_H

#include <string>
#include "sqrl.h"

class DLL_PUBLIC SqrlEncoder
{
public:
	virtual std::string *encode( std::string *dest, const std::string *src, bool append = false ) = 0;
	virtual std::string *decode( std::string *dest, const std::string *src, bool append = false ) = 0;
};
#endif // SQRLENCODER_H
