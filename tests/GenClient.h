#pragma once

#include "SqrlClientAsync.h"
#include "SqrlAction.h"
#include "SqrlActionSave.h"

class GenClient : public SqrlClientAsync
{
	void onSend(
		SqrlAction *t,
		SqrlString url, SqrlString payload ) {
		REQUIRE( false );
	}

	void onProgress(
		SqrlAction *transaction,
		int progress ) {
	}

	void onAsk(
		SqrlAction *transaction,
		SqrlString message, SqrlString firstButton, SqrlString secondButton ) {
		REQUIRE( false );
	}

	void onAuthenticationRequired(
		SqrlAction *transaction,
		Sqrl_Credential_Type credentialType ) {
		switch( credentialType ) {
		case SQRL_CREDENTIAL_NEW_PASSWORD:
		case SQRL_CREDENTIAL_PASSWORD:
			transaction->authenticate( credentialType, "password", 8 );
			break;
		default:
			REQUIRE( false );
		}
	}

	void onSelectUser( SqrlAction *transaction ) {
		REQUIRE( false );
	}
	void onSelectAlternateIdentity( SqrlAction *transaction ) {
		REQUIRE( false );
	}
	void onSaveSuggested( SqrlUser *user ) {
		new SqrlActionSave( user, "file://test2.sqrl" );
	}
	void onActionComplete( SqrlAction *action ) {
		this->completed++;
	}
public:
	int completed = 0;
};
