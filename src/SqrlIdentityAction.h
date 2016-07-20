#pragma once

#include "sqrl.h"
#include "SqrlAction.h"

class DLL_PUBLIC SqrlIdentityAction : public SqrlAction
{
	friend class SqrlUser;
	friend class SqrlActionSave;

public:
	SqrlIdentityAction( SqrlUser *user );


protected:
	void onRelease();
};