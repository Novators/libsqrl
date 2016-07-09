#include "stdafx.h"
#include "CppUnitTest.h"

#include "sqrl_expert.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libsqrltest
{
	char StorageTests_myPassword[32];

	bool StorageTests_onAuthenticationRequired(
		Sqrl_Transaction t,
		Sqrl_Credential_Type credentialType)
	{
		char *cred = NULL;
		uint8_t len;
		Sqrl_User user = sqrl_transaction_user(t);

		switch (credentialType) {
		case SQRL_CREDENTIAL_PASSWORD:
			printf("   REQ: Password\n");
			cred = (char*)malloc(strlen(StorageTests_myPassword) + 1);
			strcpy(cred, StorageTests_myPassword);
			break;
		case SQRL_CREDENTIAL_HINT:
			printf("   REQ: Hint\n");
			len = sqrl_user_get_hint_length(user);
			cred = (char*)malloc(len + 1);
			strncpy(cred, StorageTests_myPassword, len);
			break;
		case SQRL_CREDENTIAL_RESCUE_CODE:
			printf("Rescue Code Requested, but not needed!\n");
			exit(1);
		default:
			return false;
		}
		sqrl_client_authenticate(t, credentialType, cred, strlen(cred));
		if (cred) {
			free(cred);
		}
		return true;
	}

	char transactionType[11][10] = {
		"UNKNWN",
		"IDENT",
		"DISABL",
		"ENABLE",
		"REMOVE",
		"SAVE",
		"RECOVR",
		"REKEY",
		"UNLOCK",
		"LOCK",
		"LOAD"
	};
	int onProgress(Sqrl_Transaction transaction, int p)
	{
		return 1;
	}


	TEST_CLASS(StorageTests)
	{
	public:
		TEST_CLASS_INITIALIZE(InitializeSqrl)
		{
			sqrl_init();
			Sqrl_Client_Callbacks cbs;
			memset(&cbs, 0, sizeof(Sqrl_Client_Callbacks));
			cbs.onAuthenticationRequired = StorageTests_onAuthenticationRequired;
			cbs.onProgress = onProgress;
			sqrl_client_set_callbacks(&cbs);
		}

		TEST_METHOD(StorageTest)
		{
			strcpy(StorageTests_myPassword, "the password");
			bool bError = false;
			Sqrl_Storage storage = NULL;
			Sqrl_User user = NULL;
			uint8_t *key = NULL;

			storage = sqrl_storage_create();
			sqrl_storage_load_from_file(storage, "test1.sqrl");
			if (!sqrl_storage_block_exists(storage, SQRL_BLOCK_USER)
				|| !sqrl_storage_block_exists(storage, SQRL_BLOCK_RESCUE))
			{
				printf("Bad Blocks\n");
				exit(1);
			}
			storage = sqrl_storage_destroy(storage);

		}

		TEST_CLASS_CLEANUP(StopSqrl)
		{
			sqrl_stop();
		}
	};

}