#pragma once

#include "stdafx.h"
#include "CppUnitTest.h"
#include "SqrlClientAsync.h"
#include "SqrlAction.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

class NullClient : public SqrlClientAsync
{
	void onSend( SqrlAction *t, std::string url, std::string payload ) {
		Assert::Fail();
	}

	void onProgress(
		SqrlAction *action,
		int progress ) {
		Assert::Fail();
	}

	void onAsk(
		SqrlAction *action,
		std::string message, std::string firstButton, std::string secondButton ) {
		Assert::Fail();
	}

	void onAuthenticationRequired(
		SqrlAction *action,
		Sqrl_Credential_Type credentialType ) {
		Assert::Fail();
	}

	void onSelectUser( SqrlAction *action ) {
		Assert::Fail();
	}
	void onSelectAlternateIdentity( SqrlAction *action ) {
		Assert::Fail();
	}
	void onSaveSuggested( SqrlUser *user ) {
		Assert::Fail();
	}
	void onActionComplete( SqrlAction *action ) {
		Assert::Fail();
	}
};
