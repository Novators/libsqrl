#include "stdafx.h"
#include "CppUnitTest.h"

#include "sqrl_client.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libsqrltest
{		
	TEST_CLASS(UriTests)
	{
	public:
		TEST_CLASS_INITIALIZE(InitializeSqrl)
		{
			sqrl_init();
		}
		
		TEST_METHOD(Uri1)
		{
			SqrlUri uri = SqrlUri("sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_SQRL);
			char *tmp = uri.getHost();
			Assert::AreEqual(tmp, "sqrlid.com/login");
			free(tmp);
			tmp = uri.getChallenge();
			Assert::AreEqual(tmp, "sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk");
			free(tmp);
			tmp = uri.getUrl();
			Assert::AreEqual(tmp, "https://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk");
			free(tmp);
			tmp = uri.getPrefix();
			Assert::AreEqual(tmp, "https://sqrlid.com");
			free(tmp);
			tmp = uri.getSFN();
			Assert::AreEqual(tmp, "SQRLid");
			free(tmp);
		}
		
		TEST_METHOD(Uri2)
		{
			SqrlUri uri = SqrlUri("sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_SQRL);
			char *tmp = uri.getHost();
			Assert::AreEqual(tmp, "sqrlid.com");
			free(tmp);
			tmp = uri.getChallenge();
			Assert::AreEqual(tmp, "sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk");
			free(tmp);
			tmp = uri.getUrl();
			Assert::AreEqual(tmp, "https://sqrlid.com/login?nut=blah&sfn=U1FSTGlk");
			free(tmp);
			tmp = uri.getPrefix();
			Assert::AreEqual(tmp, "https://sqrlid.com");
			free(tmp);
			tmp = uri.getSFN();
			Assert::AreEqual(tmp, "SQRLid");
			free(tmp);
		}
		
		TEST_METHOD(Uri3)
		{
			SqrlUri uri = SqrlUri("sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_SQRL);
			char *tmp = uri.getHost();
			Assert::AreEqual(tmp, "sqrlid.com");
			free(tmp);
			tmp = uri.getChallenge();
			Assert::AreEqual(tmp, "sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah");
			free(tmp);
			tmp = uri.getUrl();
			Assert::AreEqual(tmp, "https://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah");
			free(tmp);
			tmp = uri.getPrefix();
			Assert::AreEqual(tmp, "https://sqrlid.com:8080");
			free(tmp);
			tmp = uri.getSFN();
			Assert::AreEqual(tmp, "SQRLid");
			free(tmp);
		}
		
		TEST_METHOD(FileUri)
		{
			SqrlUri uri = SqrlUri("file://test1.sqrl");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_FILE);
			Assert::IsTrue(uri.getHostLength() == 0);
			char *tmp = uri.getUrl();
			Assert::AreEqual(tmp, "file://test1.sqrl");
			free(tmp);
			tmp = uri.getChallenge();
			Assert::AreEqual(tmp, "test1.sqrl");
			free(tmp);
			tmp = uri.getPrefix();
			Assert::IsTrue(tmp == NULL);
			free(tmp);
			tmp = uri.getSFN();
			Assert::IsTrue(tmp == NULL);
			free(tmp);
		}
		
		TEST_METHOD(SQRLUriWithoutSFN)
		{
			SqrlUri uri = SqrlUri("sqrl://sqrlid.com:8080/login?nut=blah");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_INVALID);
		}
		
		TEST_METHOD(InvalidSQRLUrl)
		{
			SqrlUri uri = SqrlUri("http://google.com");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_INVALID);
		}

		TEST_CLASS_CLEANUP(StopSqrl)
		{
			sqrl_stop();
		}
	};

}