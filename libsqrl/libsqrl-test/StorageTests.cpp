#include "stdafx.h"
#include "CppUnitTest.h"

#include "sqrl.h"
#include "Sqrlstorage.h"
#include "SqrlUri.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libsqrltest
{

	TEST_CLASS(StorageTests)
	{
	public:
		TEST_CLASS_INITIALIZE(InitializeSqrl)
		{
			sqrl_init();
		}

		TEST_METHOD(LoadFile)
		{
			bool bError = false;
			SqrlUri *fn = SqrlUri::parse( "file://test1.sqrl" );
			Assert::IsNotNull( fn );
			SqrlStorage *storage = SqrlStorage::from( fn );
			fn->release();

			Assert::IsTrue(storage->hasBlock(SQRL_BLOCK_USER));
			Assert::IsTrue(storage->hasBlock(SQRL_BLOCK_RESCUE));
			Assert::IsFalse(storage->hasBlock(5));
			UT_string *buf;
			utstring_new(buf);
			storage->save(buf, SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64);
			Assert::IsTrue(strcmp(utstring_body(buf), "SQRLDATAfQABAC0AwDR2aKohNUWypIv-Y6TeUWbko_arcPwMB9alpAkEAAAA8QAEAQ8A7uDRpBDxqJZxwUkB4y9-p5XWvAbgVMK02lvnSA_-EBHjLarjoHYdb-UEVW2rC4z2URyOcxpCeQXfGpZQyuZ3dSGiuIFI1eLFX-xnsRsRBdtJAAIAoiMr93uN8ylhOHzwlPmfVAkUAAAATne7wOsRjUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLfD_Gul4vRyrMC2pn7UBaV9lAADAAQSHK1PlkUshvEqNeCLibmJgQvveUFrPbg4bNuk47FAj5dUgaa_fQoD_KMi17Z3jDF-1fCqoqY3GRwxaW-DzYtEIORB2AsRJUgZWviZe8anbLUP5dKt1r0LyDpTCTcNmzPvfbq8y-7J7r3OH7PlKOpGrAAs2Cw1GFb3l6hDPDa5gDKs90AGiXwgqUD7_7qMBA") == 0);
			storage->release();
			utstring_free(buf);
		}

		TEST_CLASS_CLEANUP(StopSqrl)
		{
			sqrl_stop();
		}
	};

}