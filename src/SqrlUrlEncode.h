/** \file SqrlUrlEncode.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLURLENCODE_H
#define SQRLURLENCODE_H

#include "sqrl.h"
#include "SqrlEncoder.h"

namespace libsqrl
{
    class DLL_PUBLIC SqrlUrlEncode : public SqrlEncoder
    {
    public:
		SqrlUrlEncode();
		virtual SqrlString *encode( SqrlString *dest, const SqrlString *src, bool append = false );
		virtual SqrlString *decode( SqrlString *dest, const SqrlString *src, bool append = false );
	};
}
#endif // SQRLURLENCODE_H
