#include <cstdlib>
#include "stdafx.h"
#include "CppUnitTest.h"

#include "sqrl.h"
#include "Sqrlblock.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace libsqrltest
{
	TEST_CLASS(BlockTests)
	{
	public:
		TEST_CLASS_INITIALIZE(InitializeSqrl)
		{
			sqrl_init();
			srand(1);
		}

		void testString(char *a, const char *b) {
			Assert::AreEqual(a, b);
			if (a) free(a);
		}

		TEST_METHOD(SizesAndTypes)
		{
			uint16_t t, l;
			UT_string *data;
			utstring_new(data);
			SqrlBlock *block = SqrlBlock::create();
			Assert::IsTrue(block->getBlockLength() == 0);
			Assert::IsTrue(block->getBlockType() == 0);
			block->init(0, 1);
			Assert::IsTrue(block->getBlockLength() == 1);
			Assert::IsTrue(block->getBlockType() == 0);
			for (l = 0; l < 512; l++) {
				t = (rand() % 65535);
				block->init(t, l);
				utstring_renew(data);
				block->getData(data);
				Assert::IsTrue(block->getBlockLength() == l);
				Assert::IsTrue(block->getBlockType() == t);
				Assert::AreEqual(utstring_len(data), (unsigned int)l);
			}
			block->init(65535, 1);
			Assert::IsTrue(block->getBlockType() == 65535);
			Assert::IsTrue(block->getBlockLength() == 1);
			utstring_free(data);
			block->release();
		}

		TEST_METHOD(RandomAccess)
		{
			char *testString = "Bender is Great!";
			UT_string *str;
			utstring_new(str);
			SqrlBlock *block = SqrlBlock::create();
			block->init(1, (uint16_t)strlen(testString) + 2);
			block->write((uint8_t*)testString, strlen(testString));
			block->writeInt16(0);
			Assert::IsTrue(strcmp((char*)block->getDataPointer(), testString) == 0);
			block->seekBack(3, true);
			block->writeInt8((uint8_t)'?');
			Assert::IsTrue(strcmp("Bender is Great?", (char*)block->getDataPointer()) == 0);
			block->getData(str);
			block->seek(7);
			block->writeInt8((uint8_t)' ');
			block->write((uint8_t*)(utstring_body(str) + 7), 9);
			Assert::IsTrue(strcmp("Bender  is Great?", (char*)block->getDataPointer()) == 0);
			block->seek(0);
			block->writeInt8((uint8_t)'N');
			block->seek(4, true);
			block->write((uint8_t*)"er", 2);
			block->seekBack(6, true);
			block->write((uint8_t*)"ibbl", 4);
			block->seekBack(1);
			block->writeInt8((uint8_t)'!');
			Assert::IsTrue(strcmp("Nibbler is Great!", (char*)block->getDataPointer()) == 0);
			utstring_free(str);
			block->release();
		}

		TEST_CLASS_CLEANUP(StopSqrl)
		{
			sqrl_stop();
		}
	};

}