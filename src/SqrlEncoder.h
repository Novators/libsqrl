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
#include "SqrlString.h"

namespace libsqrl
{
	class DLL_PUBLIC SqrlEncoder
	{
	public:
		virtual SqrlString *encode( SqrlString *dest, const SqrlString *src, bool append = false ) = 0;
		virtual SqrlString *decode( SqrlString *dest, const SqrlString *src, bool append = false ) = 0;
	};
}
#endif // SQRLENCODER_H
