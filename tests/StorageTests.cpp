#include "catch.hpp"

#include "sqrl.h"
#include "Sqrlstorage.h"
#include "SqrlUri.h"
#include "SqrlBlock.h"
#include "SqrlString.h"
#include "NullClient.h"

using namespace libsqrl;

static void testString( char *a, const char *b ) {
    if( !a ) {
        REQUIRE( !b );
    } else {
        REQUIRE( 0 == strcmp( a, b ) );
        free( a );
    }
}


TEST_CASE( "LoadFile", "[storage]" ) {
    NullClient * client = new NullClient();
    bool bError = false;
    SqrlString filename( "file://data/test1.sqrl" );
    SqrlUri fn = SqrlUri( &filename );
    REQUIRE( fn.isValid() );
    SqrlStorage storage = SqrlStorage( &fn );

    REQUIRE( storage.hasBlock( SQRL_BLOCK_USER ) );
    REQUIRE( storage.hasBlock( SQRL_BLOCK_RESCUE ) );
    REQUIRE( !storage.hasBlock( 5 ) );
    SqrlString *buf = storage.save( SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64 );
    REQUIRE( buf );
    REQUIRE( 0 == buf->compare( "SQRLDATAfQABAC0AwDR2aKohNUWypIv-Y6TeUWbko_arcPwMB9alpAkEAAAA8QAEAQ8A7uDRpBDxqJZxwUkB4y9-p5XWvAbgVMK02lvnSA_-EBHjLarjoHYdb-UEVW2rC4z2URyOcxpCeQXfGpZQyuZ3dSGiuIFI1eLFX-xnsRsRBdtJAAIAoiMr93uN8ylhOHzwlPmfVAkUAAAATne7wOsRjUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLfD_Gul4vRyrMC2pn7UBaV9lAADAAQSHK1PlkUshvEqNeCLibmJgQvveUFrPbg4bNuk47FAj5dUgaa_fQoD_KMi17Z3jDF-1fCqoqY3GRwxaW-DzYtEIORB2AsRJUgZWviZe8anbLUP5dKt1r0LyDpTCTcNmzPvfbq8y-7J7r3OH7PlKOpGrAAs2Cw1GFb3l6hDPDa5gDKs90AGiXwgqUD7_7qMBA" ) );
    delete(buf);
    delete client;
}


TEST_CASE( "BlockSizeAndType", "[storage]" ) {
    new NullClient();
    uint16_t t, l;
    SqrlBlock *block = new SqrlBlock();
    REQUIRE( block->length() == 0 );
    REQUIRE( block->getBlockType() == 0 );
    block->init( 0, 1 );
    REQUIRE( block->length() == 4 );
    REQUIRE( block->getBlockType() == 0 );
    for( l = 4; l < 512; l++ ) {
        t = (rand() % 65535);
        block->init( t, l );
        SqrlString *data = block->getData( NULL );
        if( l == 0 ) {
            REQUIRE( !data );
        } else REQUIRE( data );
        REQUIRE( block->length() == l );
        REQUIRE( block->getBlockType() == t );
        if( data ) {
            REQUIRE( data->length() == l );
            delete data;
        }
    }
    block->init( 65535, 1 );
    REQUIRE( block->getBlockType() == 65535 );
    REQUIRE( block->length() == 4 );
    delete block;
    delete (NullClient*)NullClient::getClient();
}

TEST_CASE( "BlockRandomAccess", "[storage]" ) {
    new NullClient();
    char *testString = "Bender is Great!";
    SqrlString *str = NULL;
    SqrlBlock *block = new SqrlBlock();
    block->init( 1, (uint16_t)strlen( testString ) + 4 );
    block->write( (uint8_t*)testString, (uint16_t)strlen( testString ) );
    REQUIRE( strcmp( (char*)block->getDataPointer()+4, testString ) == 0 );
    block->seekBack( 1 );
    block->writeInt8( (uint8_t)'?' );
    REQUIRE( strcmp( "Bender is Great?", (char*)block->getDataPointer()+4 ) == 0 );
    str = block->getData( NULL );
    REQUIRE( str );
    block->seek( 11 );
    block->writeInt8( (uint8_t)' ' );
    block->write( (uint8_t*)(str->data() + 11), 9 );
    REQUIRE( strcmp( "Bender  is Great?", (char*)block->getDataPointer()+4 ) == 0 );
    block->seek( 4 );
    block->writeInt8( (uint8_t)'N' );
    block->seek( 4, true );
    block->write( (uint8_t*)"er", 2 );
    block->seekBack( 6, true );
    block->write( (uint8_t*)"ibbl", 4 );
    block->seekBack( 1 );
    block->writeInt8( (uint8_t)'!' );
    REQUIRE( strcmp( "Nibbler is Great!", (char*)block->getDataPointer()+4 ) == 0 );
    delete str;
    delete block;
    delete (NullClient*)NullClient::getClient();
}

