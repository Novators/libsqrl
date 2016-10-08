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

namespace libsqrl
{
    class DLL_PUBLIC SqrlBase56Check : public SqrlBase56
    {
    public:
		SqrlBase56Check();
        virtual SqrlString *encode( SqrlString *dest, const SqrlString *src, bool append = false ) override;
        virtual SqrlString *decode( SqrlString *dest, const SqrlString *src, bool append = false ) override;
		virtual bool validate( const SqrlString *src, size_t *error ) override;

	private:
		bool preProcess( SqrlString *base56, const SqrlString *src, size_t *error );
    };
}
#endif // SQRLBASE56CHECK_H
