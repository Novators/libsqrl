#include <cstdlib>
#include "stdafx.h"
#include "CppUnitTest.h"

#include <stdio.h>
#include <stdint.h>
#include "sqrl.h"
#include "SqrlCrypt.h"
#include "entropy.h"
#include "SqrlBase64.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace libsqrltest
{
	UT_string *sqrl_hex_encode( UT_string *dest, const uint8_t *src, size_t src_len ) {
		if( !dest ) return NULL;
		static const char tab[] = "0123456789abcdef";
		int i;
		char tmp[3] = {0};

		utstring_renew( dest );
		utstring_reserve( dest, src_len * 2 + 1 );
		for( i = 0; i < src_len; i++ ) {
			tmp[0] = tab[src[i] >> 4];
			tmp[1] = tab[src[i] & 0x0F];
			utstring_bincpy( dest, tmp, 2 );
		}
		return dest;
	}

	TEST_CLASS( CryptoTests ) {
	public:
		TEST_CLASS_INITIALIZE( InitializeSqrl ) {
			sqrl_init();
		}

		void testString( char *a, const char *b ) {
			Assert::AreEqual( a, b );
			if( a ) free( a );
		}

		TEST_METHOD( EnHash ) {
			FILE *fp = fopen( "enhash-vectors.txt", "r" );
			if( !fp ) exit( 1 );

			char line[256];
			size_t len = 0;
			UT_string *input, *output;
			utstring_new( input );
			utstring_new( output );
			uint8_t out[SQRL_KEY_SIZE];
			SqrlBase64 b64 = SqrlBase64();

			int ln = 0;
			while( fgets(line,sizeof(line),fp) ) {
				ln++;
				b64.decode( input, line, 43 );
				b64.decode( output, line + 43, 43 );
				SqrlCrypt::enHash( (uint64_t*)out, (uint64_t*)(utstring_body( input )) );
				Assert::IsTrue( memcmp( out, utstring_body( output ), 32 ) == 0 );
			}

			utstring_free( input );
			utstring_free( output );
			fclose( fp );
		}

		TEST_METHOD( EnScrypt_1i ) {
			uint8_t emptySalt[32] = {0};
			uint8_t buf[32];
			int time;
			time = SqrlCrypt::enScrypt( NULL, buf, NULL, 0, NULL, 0, 1, 9 );
			UT_string *str;
			utstring_new( str );
			sqrl_hex_encode( str, buf, 32 );
			Assert::IsTrue( strcmp( utstring_body( str ),
				"a8ea62a6e1bfd20e4275011595307aa302645c1801600ef5cd79bf9d884d911c" ) == 0 );
			utstring_free( str );
		}

		TEST_METHOD( EnScrypt_1s ) {
			uint8_t emptySalt[32] = {0};
			uint8_t buf[32], buf2[32];
			int time;
			time = SqrlCrypt::enScrypt( NULL, buf, NULL, 0, NULL, 0, 1, 9 );
			int i = SqrlCrypt::enScryptMillis( NULL, buf, NULL, 0, NULL, 0, 1000, 9 );
			time = SqrlCrypt::enScrypt( NULL, buf2, NULL, 0, NULL, 0, i, 9 );
			Assert::IsTrue( memcmp( buf, buf2, 32 ) == 0 );
		}

		TEST_METHOD( EnScrypt_100i ) {
			uint8_t emptySalt[32] = {0};
			uint8_t buf[32];
			int time;
			time = SqrlCrypt::enScrypt( NULL, buf, NULL, 0, NULL, 0, 100, 9 );
			UT_string *str;
			utstring_new( str );
			sqrl_hex_encode( str, buf, 32 );
			Assert::IsTrue( strcmp( utstring_body( str ),
				"45a42a01709a0012a37b7b6874cf16623543409d19e7740ed96741d2e99aab67" ) == 0 );
			utstring_free( str );
		}

		TEST_METHOD( EnScrypt_p123i ) {
			uint8_t emptySalt[32] = {0};
			char password[] = "password";
			size_t password_len = 8;
			uint8_t buf[32];
			int time;
			time = SqrlCrypt::enScrypt( NULL, buf, password, password_len, NULL, 0, 123, 9 );
			UT_string *str;
			utstring_new( str );
			sqrl_hex_encode( str, buf, 32 );
			Assert::IsTrue( strcmp( utstring_body( str ),
				"129d96d1e735618517259416a605be7094c2856a53c14ef7d4e4ba8e4ea36aeb" ) == 0 );
			utstring_free( str );
		}

		TEST_METHOD( EnScrypt_p123i_salt ) {
			uint8_t emptySalt[32] = {0};
			char password[] = "password";
			size_t password_len = 8;
			uint8_t buf[32];
			int time;
			time = SqrlCrypt::enScrypt( NULL, buf, password, password_len, emptySalt, 32, 123, 9 );
			UT_string *str;
			utstring_new( str );
			sqrl_hex_encode( str, buf, 32 );
			Assert::IsTrue( strcmp( utstring_body( str ),
				"2f30b9d4e5c48056177ff90a6cc9da04b648a7e8451dfa60da56c148187f6a7d" ) == 0 );
			utstring_free( str );
		}

		TEST_METHOD( IdLockKeys ) {
			uint8_t iuk[32] = {0};
			uint8_t ilk[32];
			uint8_t rlk[32] = {0xff};
			uint8_t suk[32];
			uint8_t vuk[32];
			uint8_t ursk[32];
			uint8_t tmp[32];
			SqrlBase64 b64 = SqrlBase64();

			uint8_t sig[SQRL_SIG_SIZE];
			sqrl_entropy_bytes( iuk, 32 );
			SqrlCrypt::generateIdentityLockKey( ilk, iuk );
			SqrlCrypt::generateRandomLockKey( rlk );
			SqrlCrypt::generateCurvePrivateKey( rlk );
			SqrlCrypt::generateServerUnlockKey( suk, rlk );
			SqrlCrypt::generateVerifyUnlockKey( vuk, ilk, rlk );
			SqrlCrypt::generateUnlockRequestSigningKey( ursk, suk, iuk );

			UT_string *msg;
			utstring_new( msg );
			utstring_printf( msg, "This is a test message!" );
			SqrlCrypt::generatePublicKey( tmp, ursk );
			SqrlCrypt::sign( msg, ursk, tmp, sig );

			UT_string *buf;
			utstring_new( buf );
			b64.encode( buf, iuk, SQRL_KEY_SIZE );
			printf( "IUK: %s\n", utstring_body( buf ) );
			b64.encode( buf, ilk, SQRL_KEY_SIZE );
			printf( "ILK: %s\n", utstring_body( buf ) );
			b64.encode( buf, rlk, SQRL_KEY_SIZE );
			printf( "RLK: %s\n", utstring_body( buf ) );
			b64.encode( buf, suk, SQRL_KEY_SIZE );
			printf( "SUK: %s\n", utstring_body( buf ) );
			b64.encode( buf, vuk, SQRL_KEY_SIZE );
			printf( "VUK: %s\n", utstring_body( buf ) );
			b64.encode( buf, ursk, SQRL_KEY_SIZE );
			printf( "URK: %s\n", utstring_body( buf ) );

			Assert::IsTrue( SqrlCrypt::verifySignature( msg, sig, vuk ) );
		}

		TEST_CLASS_CLEANUP( StopSqrl ) {
			sqrl_stop();
		}
	};
}