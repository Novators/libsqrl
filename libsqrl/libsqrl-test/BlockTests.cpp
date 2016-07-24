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
			char v[64];
			Sqrl_Version( v, 64 );
			std::string str( "BlockTests: " );
			str.append( v );
			Logger::WriteMessage( str.data() );
		}

		void testString(char *a, const char *b) {
			Assert::AreEqual(a, b);
			if (a) free(a);
		}

		TEST_METHOD(SizesAndTypes)
		{
			uint16_t t, l;
			SqrlBlock *block = SqrlBlock::create();
			Assert::IsTrue(block->getBlockLength() == 0);
			Assert::IsTrue(block->getBlockType() == 0);
			block->init(0, 1);
			Assert::IsTrue(block->getBlockLength() == 1);
			Assert::IsTrue(block->getBlockType() == 0);
			for (l = 0; l < 512; l++) {
				t = (rand() % 65535);
				block->init(t, l);
				std::string *data = block->getData(NULL);
				if( l == 0 ) Assert::IsNull( data );
				else Assert::IsNotNull( data );
				Assert::IsTrue(block->getBlockLength() == l);
				Assert::IsTrue(block->getBlockType() == t);
				if( data ) {
					Assert::AreEqual( data->length(), (size_t)l );
					delete data;
				}
			}
			block->init(65535, 1);
			Assert::IsTrue(block->getBlockType() == 65535);
			Assert::IsTrue(block->getBlockLength() == 1);
			block->release();
		}

		TEST_METHOD(RandomAccess)
		{
			char *testString = "Bender is Great!";
			std::string *str = NULL;
			SqrlBlock *block = SqrlBlock::create();
			block->init(1, (uint16_t)strlen(testString) + 2);
			block->write((uint8_t*)testString, strlen(testString));
			block->writeInt16(0);
			Assert::IsTrue(strcmp((char*)block->getDataPointer(), testString) == 0);
			block->seekBack(3, true);
			block->writeInt8((uint8_t)'?');
			Assert::IsTrue(strcmp("Bender is Great?", (char*)block->getDataPointer()) == 0);
			str = block->getData(NULL);
			Assert::IsNotNull( str );
			block->seek(7);
			block->writeInt8((uint8_t)' ');
			block->write((uint8_t*)(str->data() + 7), 9);
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
			delete str;
			block->release();
		}

		TEST_CLASS_CLEANUP(StopSqrl)
		{
			sqrl_stop();
		}
	};

}