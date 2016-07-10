#include "stdafx.h"
#include "CppUnitTest.h"

#include "sqrl.h"
#include "storage.h"
#include "uri.h"

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

		TEST_METHOD(StorageTest)
		{
			bool bError = false;
			SqrlStorage storage = SqrlStorage();

			SqrlUri fn = SqrlUri("file://test1.sqrl");
			storage.load(&fn);
			Assert::IsTrue(storage.hasBlock(SQRL_BLOCK_USER));
			Assert::IsTrue(storage.hasBlock(SQRL_BLOCK_RESCUE));
			Assert::IsFalse(storage.hasBlock(5));
			UT_string *buf;
			utstring_new(buf);
			storage.save(buf, SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64);
			Logger::WriteMessage(utstring_body(buf));
			utstring_free(buf);
		}

		TEST_CLASS_CLEANUP(StopSqrl)
		{
			sqrl_stop();
		}
	};

}