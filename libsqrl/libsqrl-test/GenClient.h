#pragma once

#include "stdafx.h"
#include "CppUnitTest.h"
#include "SqrlClient.h"
#include "SqrlAction.h"
#include "SqrlActionSave.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

class GenClient : public SqrlClient
{
	void onSend(
		SqrlAction *t,
		std::string url, std::string payload ) {
		Assert::Fail();
	}

	void onProgress(
		SqrlAction *transaction,
		int progress ) {
	}

	void onAsk(
		SqrlAction *transaction,
		std::string message, std::string firstButton, std::string secondButton ) {
		Assert::Fail();
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
			Assert::Fail();
		}
	}

	void onSelectUser( SqrlAction *transaction ) {
		Assert::Fail();
	}
	void onSelectAlternateIdentity( SqrlAction *transaction ) {
		Assert::Fail();
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
