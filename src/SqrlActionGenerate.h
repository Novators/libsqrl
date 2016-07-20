#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionGenerate : public SqrlIdentityAction
{
public:
	SqrlActionGenerate();
	void run();
};