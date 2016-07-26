#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"
#include "SqrlCrypt.h"

class DLL_PUBLIC SqrlActionLock : public SqrlIdentityAction
{
	friend class SqrlUser;
public:
	SqrlActionLock( SqrlUser *user );
	int run( int cs );

private:
	struct Sqrl_User_s_callback_data cbdata;
	SqrlCrypt crypt;
	uint8_t iv[12] = {0};

};