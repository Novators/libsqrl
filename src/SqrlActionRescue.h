#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionRescue : public SqrlIdentityAction
{
	SqrlActionRescue();
	void run();
};