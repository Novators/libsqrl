/** @file SqrlActionGenerate.h
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLACTIONGENERATE_H
#define SQRLACTIONGENERATE_H

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionGenerate : public SqrlIdentityAction
{
public:
	SqrlActionGenerate();
	int run( int currentState );
};
#endif // SQRLACTIONGENERATE_H
