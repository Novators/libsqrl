/** @file SqrlActionChangePassword.h
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLACTIONCHANGEPASSWORD_H
#define SQRLACTIONCHANGEPASSWORD_H

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionChangePassword : public SqrlIdentityAction
{
	SqrlActionChangePassword();
	SqrlActionChangePassword( SqrlUser *user );
	int run( int cs );
};
#endif // SQRLACTIONCHANGEPASSWORD_H
