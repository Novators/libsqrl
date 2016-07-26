#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionRekey : public SqrlIdentityAction
{
	SqrlActionRekey();
	int run( int cs );
};