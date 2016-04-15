/* storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_internal.h"

void idlock_test() 
{
	uint8_t iuk[32] = {0};
	uint8_t ilk[32];
	uint8_t rlk[32] = {0xff};
	uint8_t suk[32];
	uint8_t vuk[32];
	uint8_t ursk[32];
	uint8_t tmp[32];

	uint8_t sig[SQRL_SIG_SIZE];

	randombytes_buf( iuk, 32 );
	sqrl_gen_ilk( ilk, iuk );
	sqrl_gen_rlk( rlk );
	sqrl_curve_private_key( rlk );
	sqrl_gen_suk( suk, rlk );
	sqrl_gen_vuk( vuk, ilk, rlk );
	sqrl_gen_ursk( ursk, suk, iuk );

	UT_string *msg;
	utstring_new( msg );
	utstring_printf( msg, "This is a test message!" );
	sqrl_ed_public_key( tmp, ursk );
	sqrl_sign( msg, ursk, tmp, sig );

	UT_string *buf;
	utstring_new( buf );
	sqrl_b64u_encode( buf, iuk, SQRL_KEY_SIZE );
	printf( "IUK: %s\n", utstring_body( buf ));
	sqrl_b64u_encode( buf, ilk, SQRL_KEY_SIZE );
	printf( "ILK: %s\n", utstring_body( buf ));
	sqrl_b64u_encode( buf, rlk, SQRL_KEY_SIZE );
	printf( "RLK: %s\n", utstring_body( buf ));
	sqrl_b64u_encode( buf, suk, SQRL_KEY_SIZE );
	printf( "SUK: %s\n", utstring_body( buf ));
	sqrl_b64u_encode( buf, vuk, SQRL_KEY_SIZE );
	printf( "VUK: %s\n", utstring_body( buf ));
	sqrl_b64u_encode( buf, ursk, SQRL_KEY_SIZE );
	printf( "URK: %s\n", utstring_body( buf ));


	if( sqrl_verify_sig( msg, sig, vuk )) {
		printf( "[ PASS ] Identity Lock Key Generation\n" );
	} else {
		printf( "[ FAIL ] Identity Lock Key Generation\n" );
		exit(1);
	}
}

void enhash_test() 
{
	FILE *fp = fopen( "vectors/enhash-vectors.txt", "r" );
	if( !fp ) exit(1);

	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	UT_string *input, *output;
	utstring_new( input );
	utstring_new( output );
	uint8_t out[SQRL_KEY_SIZE];

	int ln = 0;

	while( (read = getline( &line, &len, fp )) != -1 ) {
		ln++;
		sqrl_b64u_decode( input, line, 43 );
		sqrl_b64u_decode( output, line+43, 43 );
		Sqrl_EnHash( (uint64_t*)out, (uint64_t*)(utstring_body(input)));
		if( memcmp( out, utstring_body(output), 32 ) != 0 ) {
			printf( "[ FAIL ] EnHash at line: %d\n", ln );
			exit(1);
		}
	}

	utstring_free( input );
	utstring_free( output );
	free( line );
	fclose(fp);
	printf( "[ PASS ] EnHash\n" );
}

void enscrypt_test()
{
	uint8_t emptySalt[32] = {0};
	char password[] = "password";
	size_t password_len = 12;
	uint8_t buf[32], buf2[32];
	int time;
	time = sqrl_enscrypt( buf, NULL, 0, NULL, 0, 9, 1, NULL, NULL );
	char str[128];
	sodium_bin2hex( str, 128, buf, 32 );
	if( strcmp( str, "a8ea62a6e1bfd20e4275011595307aa302645c1801600ef5cd79bf9d884d911c") == 0 ) {
		printf( "PASS [1i](%dms): %s\n", time, str );
	} else {
		printf( "FAIL [1i](%dms): %s\n", time, str );
		exit(1);
	}

	int i = sqrl_enscrypt_ms( buf, NULL, 0, NULL, 0, 9, 1000, NULL, NULL );
	time = sqrl_enscrypt( buf2, NULL, 0, NULL, 0, 9, i, NULL, NULL );
	sodium_bin2hex( str, 128, buf, 32 );
	if( 0 == memcmp( buf, buf2, 32 )) {
		printf( "PASS [1000ms](%di): %s\n", i, str );
	} else {
		printf( "FAIL [1000ms](%di): %s\n", i, str );
		sodium_bin2hex( str, 128, buf2, 32 );
		printf( "     [%di](%dms): %s\n", i, time, str );
		exit(1);
	}
	time = sqrl_enscrypt( buf, NULL, 0, NULL, 0, 9, 100, NULL, NULL );
	sodium_bin2hex( str, 128, buf, 32 );
	if( strcmp( str, "45a42a01709a0012a37b7b6874cf16623543409d19e7740ed96741d2e99aab67" ) == 0 ) {
		printf( "PASS [100i](%dms): %s\n", time, str );
	} else {
		printf( "FAIL [100i](%dms): %s\n", time, str );
		exit(1);
	}
	time = sqrl_enscrypt( buf, password, password_len, NULL, 0, 9, 123, NULL, NULL );
	sodium_bin2hex( str, 128, buf, 32 );
	if( strcmp( str, "129d96d1e735618517259416a605be7094c2856a53c14ef7d4e4ba8e4ea36aeb" ) == 0 ) {
		printf( "PASS [pw123i](%dms): %s\n", time, str );
	} else {
		printf( "FAIL [pw123i](%dms): %s\n", time, str );
		exit(1);
	}
	time = sqrl_enscrypt( buf, password, password_len, emptySalt, 32, 9, 123, NULL, NULL );
	sodium_bin2hex( str, 128, buf, 32 );
	if( strcmp( str, "2f30b9d4e5c48056177ff90a6cc9da04b648a7e8451dfa60da56c148187f6a7d" ) == 0 ) {
		printf( "PASS [Npw123i](%dms): %s\n", time, str );
	} else {
		printf( "FAIL [Npw123i](%dms): %s\n", time, str );
		exit(1);
	}
	/* 
	time = sqrl_enscrypt( buf, NULL, 0, NULL, 0, 9, 1000, NULL, NULL );
	sodium_bin2hex( str, 128, buf, 32 );
	if( strcmp( str, "3f671adf47d2b1744b1bf9b50248cc71f2a58e8d2b43c76edb1d2a2c200907f5" ) == 0 ) {
		printf( "PASS [1000i](%dms): %s\n", time, str );
	} else {
		printf( "FAIL [1000i](%dms): %s\n", time, str );
		exit(1);
	}
	*/
}

int main() 
{
	sqrl_init();
	enscrypt_test();
	idlock_test();
	enhash_test();
	exit( sqrl_stop() );
}
