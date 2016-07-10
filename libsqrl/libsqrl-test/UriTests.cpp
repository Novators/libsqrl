#include "stdafx.h"
#include "CppUnitTest.h"

#include "sqrl_client.h"
#include "sqrl_expert.h"

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
		
		void testString(char *a, const char *b) {
			Assert::AreEqual(a, b);
			if(a) free(a);
		}

		TEST_METHOD(Uri1)
		{
			SqrlUri uri = SqrlUri("sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_SQRL);
			this->testString(uri.getHost(), "sqrlid.com/login");
			char *tmp = uri.getChallenge();
			this->testString(uri.getChallenge(), "sqrl://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk");
			this->testString(uri.getUrl(), "https://sqrlid.com/login?x=6&nut=blah&sfn=U1FSTGlk");
			this->testString(uri.getPrefix(), "https://sqrlid.com");
			this->testString(uri.getSFN(), "SQRLid");
		}
		
		TEST_METHOD(Uri2)
		{
			SqrlUri uri = SqrlUri("sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_SQRL);
			this->testString(uri.getHost(), "sqrlid.com");
			this->testString(uri.getChallenge(), "sqrl://sqrlid.com/login?nut=blah&sfn=U1FSTGlk");
			this->testString(uri.getUrl(), "https://sqrlid.com/login?nut=blah&sfn=U1FSTGlk");
			this->testString(uri.getPrefix(), "https://sqrlid.com");
			this->testString(uri.getSFN(), "SQRLid");
		}
		
		TEST_METHOD(Uri3)
		{
			SqrlUri uri = SqrlUri("sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_SQRL);
			this->testString(uri.getHost(), "sqrlid.com");
			this->testString(uri.getChallenge(), "sqrl://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah");
			this->testString(uri.getUrl(), "https://sqrlid.com:8080/login?sfn=U1FSTGlk&nut=blah");
			this->testString(uri.getPrefix(), "https://sqrlid.com:8080");
			this->testString(uri.getSFN(), "SQRLid");
		}
		
		TEST_METHOD(FileUri)
		{
			SqrlUri uri = SqrlUri("file://test1.sqrl");
			Assert::IsTrue(uri.getScheme() == SQRL_SCHEME_FILE);
			Assert::IsTrue(uri.getHostLength() == 0);
			this->testString(uri.getUrl(), "file://test1.sqrl");
			this->testString(uri.getChallenge(), "test1.sqrl");
			this->testString(uri.getPrefix(), NULL);
			this->testString(uri.getSFN(), NULL);
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