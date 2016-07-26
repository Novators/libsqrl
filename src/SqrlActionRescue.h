#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionRescue : public SqrlIdentityAction
{
	SqrlActionRescue();
	int run( int cs );
};