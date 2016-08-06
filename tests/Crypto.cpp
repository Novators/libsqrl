#include "catch.hpp"

#include <cstdlib>
#include <stdio.h>
#include <stdint.h>
#include "sqrl.h"
#include "SqrlCrypt.h"
#include "SqrlEntropy.h"
#include "SqrlBase64.h"
#include "SqrlEnScrypt.h"
#include "NullClient.h"
#include "Windows.h"

using namespace std;

static void sqrl_hex_encode( SqrlString *dest, const uint8_t *src, size_t src_len ) {
	if( !dest ) return;
	static const char tab[] = "0123456789abcdef";
	size_t i;
	char tmp[3] = {0};

	dest->clear();
	dest->reserve( src_len * 2 + 1 );
	for( i = 0; i < src_len; i++ ) {
		tmp[0] = tab[src[i] >> 4];
		tmp[1] = tab[src[i] & 0x0F];
		dest->append( tmp, 2 );
	}
}

static void testString( char *a, const char *b ) {
	REQUIRE( 0 == strcmp( a, b ) );
	if( a ) free( a );
}

TEST_CASE( "EnHash" ) {
	NullClient *client = new NullClient();
	while( NullClient::getClient() == NULL ) {
		Sleep( 5 );
	}
	FILE *fp = fopen( "data/vectors/enhash-vectors.txt", "r" );
	if( !fp ) exit( 2 );

	char line[256];
	size_t len = 0;
	SqrlString input((size_t)0), output((size_t)0);
	SqrlString tmp((size_t)0), tmp2((size_t)0);
	uint8_t out[SQRL_KEY_SIZE];
	SqrlBase64 b64 = SqrlBase64();

	int ln = 0;
	while( fgets( line, sizeof( line ), fp ) ) {
		ln++;
		tmp.append( line, 43 );
		tmp2.append( line + 43, 43 );
		b64.decode( &input, &tmp );
		b64.decode( &output, &tmp2 );
		SqrlCrypt::enHash( (uint64_t*)out, (uint64_t*)(input.data()) );
		REQUIRE( 32 == output.length() );
		/*
		tmp2.clear();
		tmp2.append( out, 32 );
		b64.encode( &tmp, &tmp2 );
		b64.encode( &tmp2, &output );
		printf( "%s == %s\n", tmp.cstring(), tmp2.cstring() );
		*/
		REQUIRE( 0 == memcmp( out, output.data(), 32 ) );
		tmp.clear();
		tmp2.clear();
	}
	fclose( fp );
	delete client;
}

TEST_CASE( "EnScrypt -- 1 iteration" ) {
	NullClient *client = new NullClient();
	while( NullClient::getClient() == NULL ) {
		Sleep( 5 );
	}
	SqrlEnScrypt es = SqrlEnScrypt( NULL, NULL, NULL, 1 );
	while( !es.isFinished() ) {
		es.update();
	}
	REQUIRE( es.isSuccessful() );
	SqrlString *buf = es.getResult();
	SqrlString str;
	sqrl_hex_encode( &str, buf->cdata(), 32 );
	REQUIRE( str.compare( "a8ea62a6e1bfd20e4275011595307aa302645c1801600ef5cd79bf9d884d911c" ) == 0 );
	delete client;
}

TEST_CASE( "EnScrypt -- 1 + 1 second" ) {
	NullClient *client = new NullClient();
	while( NullClient::getClient() == NULL ) {
		Sleep( 5 );
	}
	SqrlEnScrypt es = SqrlEnScrypt( NULL, NULL, NULL, 1000, false );
	while( !es.isFinished() ) {
		es.update();
	}
	REQUIRE( es.isSuccessful() );
	uint16_t iterations = es.getIterations();
	SqrlString *buf = es.getResult();
	SqrlEnScrypt es2 = SqrlEnScrypt( NULL, NULL, NULL, iterations );
	while( !es2.isFinished() ) {
		es2.update();
	}
	REQUIRE( es2.isSuccessful() );
	SqrlString *buf2 = es2.getResult();
	REQUIRE( buf->compare( buf2 ) == 0 );
	delete client;
}

TEST_CASE( "EnScrypt 100 iterations" ) {
	NullClient *client = new NullClient();
	while( NullClient::getClient() == NULL ) {
		Sleep( 5 );
	}
	SqrlEnScrypt es = SqrlEnScrypt( NULL, NULL, NULL, 100 );
	while( !es.isFinished() ) {
		es.update();
	}
	REQUIRE( es.isSuccessful() );

	SqrlString *buf = es.getResult();
	SqrlString str;
	sqrl_hex_encode( &str, buf->cdata(), 32 );
	REQUIRE( str.compare( "45a42a01709a0012a37b7b6874cf16623543409d19e7740ed96741d2e99aab67" ) == 0 );
	delete client;
}

TEST_CASE( "EnScrypt password, 123 iterations" ) {
	NullClient *client = new NullClient();
	while( NullClient::getClient() == NULL ) {
		Sleep( 5 );
	}
	SqrlString pw( "password" );
	SqrlEnScrypt es = SqrlEnScrypt( NULL, &pw, NULL, 123 );
	while( !es.isFinished() ) {
		es.update();
	}
	REQUIRE( es.isSuccessful() );
	SqrlString *buf = es.getResult();
	SqrlString str;
	sqrl_hex_encode( &str, buf->cdata(), 32 );
	REQUIRE( str.compare( "129d96d1e735618517259416a605be7094c2856a53c14ef7d4e4ba8e4ea36aeb" ) == 0 );
	delete client;
}

TEST_CASE( "EnScrypt password, salt, 123 iterations" ) {
	NullClient *client = new NullClient();
	while( NullClient::getClient() == NULL ) {
		Sleep( 5 );
	}
	SqrlString pw( "password" );
	SqrlString salt( 32 );
	salt.append( (char)0, 32 );
	SqrlEnScrypt es = SqrlEnScrypt( NULL, &pw, &salt, 123 );
	while( !es.isFinished() ) {
		es.update();
	}
	REQUIRE( es.isSuccessful() );
	SqrlString *buf = es.getResult();
	SqrlString str;
	sqrl_hex_encode( &str, buf->cdata(), 32 );
	REQUIRE( str.compare( "2f30b9d4e5c48056177ff90a6cc9da04b648a7e8451dfa60da56c148187f6a7d" ) == 0 );
	delete client;
}

TEST_CASE( "Identity Lock Keys" ) {
	NullClient *client = new NullClient();
	uint8_t iuk[32] = {0};
	uint8_t ilk[32];
	uint8_t rlk[32] = {0xff};
	uint8_t suk[32];
	uint8_t vuk[32];
	uint8_t ursk[32];
	uint8_t tmp[32];
	SqrlBase64 b64 = SqrlBase64();

	uint8_t sig[SQRL_SIG_SIZE];
	SqrlEntropy::bytes( iuk, 32 );
	SqrlCrypt::generateIdentityLockKey( ilk, iuk );
	SqrlCrypt::generateRandomLockKey( rlk );
	SqrlCrypt::generateCurvePrivateKey( rlk );
	SqrlCrypt::generateServerUnlockKey( suk, rlk );
	SqrlCrypt::generateVerifyUnlockKey( vuk, ilk, rlk );
	SqrlCrypt::generateUnlockRequestSigningKey( ursk, suk, iuk );

	SqrlString *msg = new SqrlString( "This is a test message!" );
	SqrlCrypt::generatePublicKey( tmp, ursk );
	SqrlCrypt::sign( msg, ursk, tmp, sig );

	SqrlString buf;
	SqrlString ts;
	ts.append( (char*)iuk, SQRL_KEY_SIZE );
	b64.encode( &buf, &ts );
	ts.clear();
	ts.append( (char*)ilk, SQRL_KEY_SIZE );
	b64.encode( &buf, &ts );
	ts.clear();
	ts.append( (char*)rlk, SQRL_KEY_SIZE );
	b64.encode( &buf, &ts );
	ts.clear();
	ts.append( (char*)suk, SQRL_KEY_SIZE );
	b64.encode( &buf, &ts );
	ts.clear();
	ts.append( (char*)vuk, SQRL_KEY_SIZE );
	b64.encode( &buf, &ts );
	ts.clear();
	ts.append( (char*)ursk, SQRL_KEY_SIZE );
	b64.encode( &buf, &ts );

	REQUIRE( SqrlCrypt::verifySignature( msg, sig, vuk ) );
	delete client;
}
