#pragma once

#include "../src/SqrlClientAsync.h"
#include "SqrlAction.h"

using namespace std;

class NullClient : public SqrlClientAsync
{
	void onSend( SqrlAction *t, std::string url, std::string payload ) {
		REQUIRE( false );
	}

	void onProgress(
		SqrlAction *action,
		int progress ) {
		REQUIRE( false );
	}

	void onAsk(
		SqrlAction *action,
		std::string message, std::string firstButton, std::string secondButton ) {
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
