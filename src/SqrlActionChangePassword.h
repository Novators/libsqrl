#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"
#include "SqrlUser.fwd.h"

class DLL_PUBLIC SqrlActionChangePassword : public SqrlIdentityAction
{
	SqrlActionChangePassword();
	SqrlActionChangePassword( SqrlUser *user );
	void run();
};