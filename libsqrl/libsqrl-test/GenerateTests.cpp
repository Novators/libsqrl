#include <cstdlib>
#include "stdafx.h"
#include "CppUnitTest.h"

#include <Windows.h>
#include "sqrl.h"
#include "SqrlClient.h"
#include "SqrlUser.h"
#include "SqrlActionGenerate.h"
#include "SqrlActionSave.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace libsqrltest
{
	int completed = 0;
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
			completed++;
		}
	};

	TEST_CLASS( GenerateTests ) {
public:
	TEST_CLASS_INITIALIZE( InitializeSqrl ) {
		sqrl_init();
		new GenClient();
		char v[64];
		Sqrl_Version( v, 64 );
		std::string str( "GenerateTests: " );
		str.append( v );
		Logger::WriteMessage( str.data() );
	}

	TEST_METHOD( generateId ) {
		new SqrlActionGenerate();
		while( completed < 2 ) {
			Sleep( 100 );
		}
	}

	TEST_CLASS_CLEANUP( StopSqrl ) {
		delete GenClient::getClient();
		sqrl_stop();
	}
	};

}