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
		SqrlEncoder();
		SqrlEncoder( const char *alphabet );
        virtual SqrlString *encode( SqrlString *dest, const SqrlString *src, bool append = false );
        virtual SqrlString *decode( SqrlString *dest, const SqrlString *src, bool append = false );
		virtual bool validate( const SqrlString *src, size_t *error );

	protected:
		const char *alphabet;
		bool reverseMath;
    };
}
#endif // SQRLENCODER_H
