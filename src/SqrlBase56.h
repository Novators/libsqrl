/** \file SqrlBase56.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLBASE56_H
#define SQRLBASE56_H

#include "sqrl.h"
#include "SqrlEncoder.h"

namespace libsqrl
{
    class DLL_PUBLIC SqrlBase56 : SqrlEncoder
    {
    public:
        virtual SqrlString *encode( SqrlString *dest, const SqrlString *src, bool append = false );
        virtual SqrlString *decode( SqrlString *dest, const SqrlString *src, bool append = false );

    protected:
        const char *alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";

    };
}
#endif // SQRLBASE56_H
