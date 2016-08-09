#pragma once

#include "../src/SqrlClientAsync.h"
#include "SqrlAction.h"

using namespace std;
using namespace libsqrl;

class NullClient : public SqrlClientAsync
{
	void onSend( SqrlAction *t, SqrlString url, SqrlString payload ) {
		REQUIRE( false );
	}

	void onProgress(
		SqrlAction *action,
		int progress ) {
		REQUIRE( false );
	}

	void onAsk(
		SqrlAction *action,
		SqrlString message, SqrlString firstButton, SqrlString secondButton ) {
		REQUIRE( false );
	}

	void onAuthenticationRequired(
		SqrlAction *action,
		Sqrl_Credential_Type credentialType ) {
		REQUIRE( false );
	}

	void onSelectUser( SqrlAction *action ) {
		REQUIRE( false );
	}
	void onSelectAlternateIdentity( SqrlAction *action ) {
		REQUIRE( false );
	}
	void onSaveSuggested( SqrlUser *user ) {
		REQUIRE( false );
	}
	void onActionComplete( SqrlAction *action ) {
		REQUIRE( false );
	}
};
