#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionLock : public SqrlIdentityAction
{
	friend class SqrlUser;
public:
	SqrlActionLock( SqrlUser *user );
	int run( int cs );
};