#pragma once

#include "SqrlAction.fwd.h"
#include "SqrlUser.fwd.h"
#include "SqrlClient.fwd.h"

class DLL_PUBLIC SqrlAction
{
	friend class SqrlUser;
	friend class SqrlIdentityAction;

public:
	/* virtual */ void run();
	bool isFinished();
	
	void hold();
	SqrlAction *release();
	void setUser(SqrlUser *user);
	SqrlUser* getUser();
	static int countTransactions();
	SqrlUri *getUri();
	void setUri(SqrlUri *uri);
	void authenticate( Sqrl_Credential_Type credentialType,
		const char *credential, size_t credentialLength );
	
protected:
	void onRelease();

	SqrlAction();
	SqrlUser *user;
	SqrlUri *uri;
	SqrlMutex mutex;
	int referenceCount;
	int runState;
	bool finished;
	bool running;
};

