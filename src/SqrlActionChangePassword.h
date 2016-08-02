#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionChangePassword : public SqrlIdentityAction
{
	SqrlActionChangePassword();
	SqrlActionChangePassword( SqrlUser *user );
	int run( int cs );
};