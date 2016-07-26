#include "stdafx.h"
#include "CppUnitTest.h"

#include "sqrl.h"
#include "Sqrlstorage.h"
#include "SqrlUri.h"
#include "SqrlBlock.h"
#include "NullClient.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libsqrltest
{

	TEST_CLASS(StorageTests)
	{
	public:
		TEST_CLASS_INITIALIZE(InitializeSqrl)
		{
			char v[64];
			Sqrl_Version( v, 64 );
			std::string str( "StorageTests: " );
			str.append( v );
			Logger::WriteMessage( str.data() );
		}

		TEST_METHOD(LoadFile)
		{
			new NullClient();
			bool bError = false;
			SqrlUri *fn = SqrlUri::parse( "file://test1.sqrl" );
			Assert::IsNotNull( fn );
			SqrlStorage *storage = SqrlStorage::from( fn );
			fn->release();
			Assert::IsNotNull( storage );

			Assert::IsTrue(storage->hasBlock(SQRL_BLOCK_USER));
			Assert::IsTrue(storage->hasBlock(SQRL_BLOCK_RESCUE));
			Assert::IsFalse(storage->hasBlock(5));
			std::string *buf = storage->save( SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64 );
			Assert::IsNotNull( buf );
			Assert::IsTrue(0 == buf->compare( "SQRLDATAfQABAC0AwDR2aKohNUWypIv-Y6TeUWbko_arcPwMB9alpAkEAAAA8QAEAQ8A7uDRpBDxqJZxwUkB4y9-p5XWvAbgVMK02lvnSA_-EBHjLarjoHYdb-UEVW2rC4z2URyOcxpCeQXfGpZQyuZ3dSGiuIFI1eLFX-xnsRsRBdtJAAIAoiMr93uN8ylhOHzwlPmfVAkUAAAATne7wOsRjUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLfD_Gul4vRyrMC2pn7UBaV9lAADAAQSHK1PlkUshvEqNeCLibmJgQvveUFrPbg4bNuk47FAj5dUgaa_fQoD_KMi17Z3jDF-1fCqoqY3GRwxaW-DzYtEIORB2AsRJUgZWviZe8anbLUP5dKt1r0LyDpTCTcNmzPvfbq8y-7J7r3OH7PlKOpGrAAs2Cw1GFb3l6hDPDa5gDKs90AGiXwgqUD7_7qMBA"));
			storage->release();
			delete(buf);
			delete NullClient::getClient();
		}

		void testString( char *a, const char *b ) {
			Assert::AreEqual( a, b );
			if( a ) free( a );
		}

		TEST_METHOD( BlockSizeAndType ) {
			new NullClient();
			uint16_t t, l;
			SqrlBlock *block = SqrlBlock::create();
			Assert::IsTrue( block->getBlockLength() == 0 );
			Assert::IsTrue( block->getBlockType() == 0 );
			block->init( 0, 1 );
			Assert::IsTrue( block->getBlockLength() == 1 );
			Assert::IsTrue( block->getBlockType() == 0 );
			for( l = 0; l < 512; l++ ) {
				t = (rand() % 65535);
				block->init( t, l );
				std::string *data = block->getData( NULL );
				if( l == 0 ) Assert::IsNull( data );
				else Assert::IsNotNull( data );
				Assert::IsTrue( block->getBlockLength() == l );
				Assert::IsTrue( block->getBlockType() == t );
				if( data ) {
					Assert::AreEqual( data->length(), (size_t)l );
					delete data;
				}
			}
			block->init( 65535, 1 );
			Assert::IsTrue( block->getBlockType() == 65535 );
			Assert::IsTrue( block->getBlockLength() == 1 );
			block->release();
			delete NullClient::getClient();
		}

		TEST_METHOD( BlockRandomAccess ) {
			new NullClient();
			char *testString = "Bender is Great!";
			std::string *str = NULL;
			SqrlBlock *block = SqrlBlock::create();
			block->init( 1, (uint16_t)strlen( testString ) + 2 );
			block->write( (uint8_t*)testString, strlen( testString ) );
			block->writeInt16( 0 );
			Assert::IsTrue( strcmp( (char*)block->getDataPointer(), testString ) == 0 );
			block->seekBack( 3, true );
			block->writeInt8( (uint8_t)'?' );
			Assert::IsTrue( strcmp( "Bender is Great?", (char*)block->getDataPointer() ) == 0 );
			str = block->getData( NULL );
			Assert::IsNotNull( str );
			block->seek( 7 );
			block->writeInt8( (uint8_t)' ' );
			block->write( (uint8_t*)(str->data() + 7), 9 );
			Assert::IsTrue( strcmp( "Bender  is Great?", (char*)block->getDataPointer() ) == 0 );
			block->seek( 0 );
			block->writeInt8( (uint8_t)'N' );
			block->seek( 4, true );
			block->write( (uint8_t*)"er", 2 );
			block->seekBack( 6, true );
			block->write( (uint8_t*)"ibbl", 4 );
			block->seekBack( 1 );
			block->writeInt8( (uint8_t)'!' );
			Assert::IsTrue( strcmp( "Nibbler is Great!", (char*)block->getDataPointer() ) == 0 );
			delete str;
			block->release();
			delete NullClient::getClient();
		}

		TEST_CLASS_CLEANUP(StopSqrl)
		{
		}
	};

}