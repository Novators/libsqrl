#pragma once

#include <climits>
#include "sqrl.h"

#define SQRL_ACTION_RUNNING 0
#define SQRL_ACTION_SUCCESS 1
#define SQRL_ACTION_FAIL -1
#define SQRL_ACTION_CANCELED -2

#define SQRL_ACTION_STATE_DELETE INT_MIN

class DLL_PUBLIC SqrlAction
{
	friend class SqrlClient;
	friend class SqrlClientAsync;
	friend class SqrlUser;
	friend class SqrlIdentityAction;

public:
	SqrlAction();

	void cancel();
	void authenticate( Sqrl_Credential_Type credentialType,
		const char *credential, size_t credentialLength );

	SqrlUser* getUser();
	void setUser(SqrlUser *user);

	SqrlUri *getUri();
	void setUri(SqrlUri *uri);

protected:
	~SqrlAction();
	virtual int run( int currentState ) = 0;

	int retActionComplete( int status );
	bool exec();
	void onRelease();

	SqrlUser *user;
	SqrlUri *uri;
	int state;
	int status;
	bool shouldCancel;
};

