#include <cstdlib>
#include "stdafx.h"
#include "CppUnitTest.h"

#include "sqrl.h"
#include "SqrlClient.h"
#include "SqrlUser.h"
#include "SqrlActionGenerate.h"
#include "SqrlActionSave.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace libsqrltest
{
	class GenClient : public SqrlClient
	{
		void onSend(
			SqrlAction *t,
			const char *url, size_t url_len,
			const char *payload, size_t payload_len ) {
			Assert::Fail();
		}

		int onProgress(
			SqrlAction *transaction,
			int progress ) {
			return 0;
		}

		void onAsk(
			SqrlAction *transaction,
			const char *message, size_t message_len,
			const char *firstButton, size_t firstButton_len,
			const char *secondButton, size_t secondButton_len ) {
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
			SqrlActionSave *save = new SqrlActionSave( user, "file://test2.sqrl" );
			save->setEncodingType( SQRL_ENCODING_BINARY );
			save->run();
		}
		void onActionComplete( SqrlAction *action ) {

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
		SqrlActionGenerate *a = new SqrlActionGenerate();
		a->run();
	}

	TEST_CLASS_CLEANUP( StopSqrl ) {
		delete GenClient::getClient();
		sqrl_stop();
	}
	};

}