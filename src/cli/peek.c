/** @file enscrypt_bin.c

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
 **/

#define N_FACTOR 9

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "../sqrl_internal.h"


long duration = 0;
long iterations = 0;
uint8_t *salt = NULL;
char *password = NULL;
char *rc = NULL;
char *text = NULL;
char *filename = NULL;
bool showHelp = false;
bool verbose = true;
int nextProgress = 2;

char help[] = "Peek (inspect SQRL identity)\n\
    Usage: peek password [rc] SQRLDATA\n\
    	   peek password [rc] filename\n\
           peek -h\n\n\
    password -- The password used for the Type 1 Block.\n\
        Use \"quotes\" if password contains spaces or special characters.\n\
    rc       -- Rescue Code\n\
        This should be 24 decimal digits.  Do not include group separators.\n\
    SQRLDATA -- Encoded Identity\n\
    filename -- File containing Identity\n";

int progress( int p, void *cb_data )
{
	const char sym[] = "|****";
	while( p >= nextProgress ) {
		if( verbose ) {
			if( nextProgress == 100 ) {
				printf( "]" );
			} else {
				printf( "%c", sym[nextProgress%5] );
			}
		}
		nextProgress += 2;
	}
	fflush( stdout );
	return 1;
}

void printFlags( uint16_t flags ) {
	if( flags & SQRL_OPTION_CHECK_FOR_UPDATES ) printf( "                     CHECK_FOR_UPDATES\n" );
	if( flags & SQRL_OPTION_ASK_FOR_IDENTITY ) printf( "                     ASK_FOR_IDENTITY\n" );
	if( flags & SQRL_OPTION_REQUEST_SQRL_ONLY ) printf( "                     REQUEST_SQRL_ONLY\n" );
	if( flags & SQRL_OPTION_REQUEST_ID_LOCK ) printf( "                     REQUEST_ID_LOCK\n" );
	if( flags & SQRL_OPTION_WARN_MITM ) printf( "                     WARN_MITM\n" );
	if( flags & SQRL_OPTION_CLEAR_HINT_SUSPEND ) printf( "                     CLEAR_HINT_ON_SUSPEND\n" );
	if( flags & SQRL_OPTION_CLEAR_HINT_USER_SWITCH ) printf( "                     CLEAR_HINT_ON_USER_SWITCH\n" );
	if( flags & SQRL_OPTION_CLEAR_HINT_IDLE ) printf( "                     CLEAR_HINT_ON_IDLE\n" );
}

void printBreak( char *str, int brk )
{
	int l = strlen( str );
	int i = 0;

	printf( "  " );
	while( i < l ) {
		printf( "%c", str[i++] );
		if( (i < l) && ((i % brk) == 0 )) {
			printf( "\n  " );
		}
	}
	printf( "\n" );
}

void printTwoByFour( char *str )
{
	int l = strlen( str );
	int i = 0;
	int j;

	printf( "    " );
	while( i < l ) {
		printf( "%c", str[i++] );
		if( (i < l) && ((i % 48) == 0) ) {
			printf( "\n    " );
			continue;	
		}
		if( (i % 4) == 0 ) {
			printf( " " );
		}
	}
	printf( "\n" );
}

void printInFours( char *str )
{
	int l = strlen( str );
	int i = 0;
	int j;

	while( i < l ) {
		printf( "%c", str[i++] );
		if( (i < l) && ((i % 32) == 0) ) {
			printf( "\n                     " );
			continue;	
		}
		if( (i % 4) == 0 ) {
			printf( " " );
		}
	}
	printf( "\n" );
}

void printBlock1( Sqrl_Storage storage )
{
	Sqrl_User user;
	Sqrl_Block block;
	sqrl_block_clear( &block );
	uint16_t d16, ptl;
	uint8_t buf[512];
	uint8_t salt[16];
	uint8_t d8, nFactor;
	uint32_t d32, iterations;
	char str[512];
	uint8_t *ptr;

	if( sqrl_storage_block_get( storage, &block, SQRL_BLOCK_USER )) {
		printf( "Block 1:\n" );
		d16 = sqrl_block_read_int16( &block );
		sqrl_block_seek( &block, 0 );
		sqrl_block_read( &block, buf, d16 );
		sodium_bin2hex( str, 512, buf, d16 );
		printTwoByFour( str );
		sqrl_block_seek( &block, 2 );
		printf( "  Block Length:      %u\n", d16 );
		d16 = sqrl_block_read_int16( &block );
		printf( "  Block Type:        %u\n", d16 );
		ptl = sqrl_block_read_int16( &block );
		printf( "  PT Length:         %u\n", ptl );
		sqrl_block_read( &block, buf, 12 );
		sodium_bin2hex( str, 512, buf, 12 );
		printf( "  AES-GCM IV:        " );
		printInFours( str );
		sqrl_block_read( &block, salt, 16 );
		sodium_bin2hex( str, 512, salt, 16 );
		printf( "  Scrypt Salt:       " );
		printInFours( str );
		nFactor = sqrl_block_read_int8( &block );
		printf( "  N-Factor:          %u\n", nFactor );
		iterations = sqrl_block_read_int32( &block );
		printf( "  Iteration Count:   %u\n", iterations );
		d16 = sqrl_block_read_int16( &block );
		buf[0] = d16 & 0xFF00;
		buf[1] = d16 & 0x00FF;
		sodium_bin2hex( str, 512, buf, 2 );
		printf( "  Flags:             %u (0x%s)\n", d16, str );
		printFlags( d16 );
		d8 = sqrl_block_read_int8( &block );
		printf( "  Hint Length:       %u\n", d8 );
		d8 = sqrl_block_read_int8( &block );
		printf( "  PW Verify Seconds: %u\n", d8 );
		d16 = sqrl_block_read_int16( &block );
		printf( "  Timeout Minutes:   %u\n", d16 );
		sqrl_block_read( &block, buf, 64 + 16 );
		printf( "  Encrypted IMK:     " );
		sodium_bin2hex( str, 512, buf, 32 );
		printInFours( str );
		printf( "  Encrypted ILK:     " );
		sodium_bin2hex( str, 512, buf + 32, 32 );
		printInFours( str );
		printf( "  Verification Tag:  " );
		sodium_bin2hex( str, 512, buf + 64, 16 );
		printInFours( str );
		sqrl_block_seek( &block, 0 );
		sqrl_block_read( &block, buf, ptl );
		printf( "  AAD (%u):\n", ptl );
		sodium_bin2hex( str, 512, buf, ptl );
		printTwoByFour( str );
		sqrl_block_read( &block, buf, 64 );
		printf( "  Cipher Text (64):\n" );
		sodium_bin2hex( str, 512, buf, 64 );
		printTwoByFour( str );
		sqrl_block_seek( &block, 109 );
		sqrl_block_read( &block, buf, 16 );
		sodium_bin2hex( str, 512, buf, 16 );
		printf( "  Tag (16):\n" );
		printTwoByFour( str );
		sqrl_block_free( &block );
		if( password ) {
			printf( "  Using Password:    %s\n", password );
			if( 0 < sqrl_enscrypt( buf, password, strlen( password ),
				salt, 16, nFactor, iterations, NULL, NULL )) {
				sodium_bin2hex( str, 512, buf, 32 );
				printf( "  AES-GCM Key:\n" );
				printTwoByFour( str );
			}

			int sqrl_enscrypt( 
				uint8_t *buf, 
				const char *password, 
				size_t password_len, 
				const uint8_t *salt, 
				uint8_t salt_len,
				uint8_t nFactor,
				uint16_t iterations,
				enscrypt_progress_fn cb_ptr, 
				void *cb_data );
			user = sqrl_user_create();
			ptr = (uint8_t*)sqrl_user_password( user );
			size_t *pl = sqrl_user_password_length( user );
			*pl = strlen( password );
			strcpy( (char*)ptr, password );
			if( SQRL_STATUS_OK == sqrl_user_load_with_password( user, storage, NULL, NULL )) {
				printf( "  Decryption:\n" );
				ptr = sqrl_user_key( user, KEY_MK );
				sodium_bin2hex( str, 512, ptr, 32 );
				printf( "    Decrypted IMK:   " );
				printInFours( str );
				ptr = sqrl_user_key( user, KEY_ILK );
				sodium_bin2hex( str, 512, ptr, 32 );
				printf( "    Decrypted ILK:   " );
				printInFours( str );
			} else {
				printf( "  Decryption:        Failed\n" );
				return;
			}
		}
	} else {
		printf( "Block 1 Not found.\n" );
		return;
	}
}

void printBlock2( Sqrl_Storage storage )
{
	Sqrl_User user;
	Sqrl_Block block;
	sqrl_block_clear( &block );
	uint16_t d16;
	uint8_t buf[512];
	uint8_t d8;
	uint32_t d32;
	char str[512];
	uint8_t *ptr;
	Sqrl_Status status;

	if( sqrl_storage_block_get( storage, &block, SQRL_BLOCK_RESCUE )) {
		printf( "Block 2:\n" );
		d16 = sqrl_block_read_int16( &block );
		printf( "  Block Length:      %u\n", d16 );
		d16 = sqrl_block_read_int16( &block );
		printf( "  Block Type:        %u\n", d16 );
		sqrl_block_read( &block, buf, 16 );
		sodium_bin2hex( str, 512, buf, 16 );
		printf( "  Scrypt Salt:       " );
		printInFours( str );
		d8 = sqrl_block_read_int8( &block );
		printf( "  N-Factor:          %u\n", d8 );
		d32 = sqrl_block_read_int32( &block );
		printf( "  Iteration Count:   %u\n", d32 );
		sqrl_block_read( &block, buf, 32 + 16 );
		printf( "  Encrypted IUK:     " );
		sodium_bin2hex( str, 512, buf, 32 );
		printInFours( str );
		printf( "  Verification Tag:  " );
		sodium_bin2hex( str, 512, buf + 32, 16 );
		printInFours( str );
		sqrl_block_free( &block );
		if( rc && strlen( rc ) == 24 ) {
			printf( "  Rescue Code:       %s\n", rc );
			user = sqrl_user_create();
			ptr = (uint8_t*)sqrl_user_key( user, KEY_RESCUE_CODE );
			strcpy( (char*)ptr, rc );
			status = sqrl_user_load_with_rescue_code( user, storage, NULL, NULL );
			if( status == SQRL_STATUS_OK ) {
				printf( "  Decryption:\n" );
				ptr = sqrl_user_key( user, KEY_IUK );
				sodium_bin2hex( str, 512, ptr, 32 );
				printf( "    Decrypted IUK:   " );
				printInFours( str );
			} else {
				printf( "  Decryption:        Failed (%d)\n", status );
				return;
			}
		}
	} else {
		printf( "Block 2 Not found.\n" );
		return;
	}

}

void printBlock3( Sqrl_Storage storage )
{
	Sqrl_User user;
	Sqrl_Block block;
	sqrl_block_clear( &block );
	uint16_t d16;
	uint8_t buf[512];
	uint8_t d8;
	uint32_t d32;
	char str[512];
	uint8_t *ptr;
	Sqrl_Status status;

	if( sqrl_storage_block_get( storage, &block, SQRL_BLOCK_PREVIOUS )) {
		printf( "Block 3:\n" );
		d16 = sqrl_block_read_int16( &block );
		printf( "  Block Length:      %u\n", d16 );
		d16 = sqrl_block_read_int16( &block );
		printf( "  Block Type:        %u\n", d16 );
		sqrl_block_read( &block, buf, (32*4)+16 );
		ptr = buf;
		sodium_bin2hex( str, 512, ptr, 32 );
		printf( "  Encrypted PIUK0:   " );
		printInFours( str );
		ptr += 32;
		sodium_bin2hex( str, 512, ptr, 32 );
		printf( "  Encrypted PIUK1:   " );
		printInFours( str );
		ptr += 32;
		sodium_bin2hex( str, 512, ptr, 32 );
		printf( "  Encrypted PIUK2:   " );
		printInFours( str );
		ptr += 32;
		sodium_bin2hex( str, 512, ptr, 32 );
		printf( "  Encrypted PIUK3:   " );
		printInFours( str );
		ptr += 32;
		sodium_bin2hex( str, 512, ptr, 16 );
		printf( "  Verification Tag:  " );
		printInFours( str );
		sqrl_block_free( &block );
		if( password ) {
			user = sqrl_user_create();
			ptr = (uint8_t*)sqrl_user_password( user );
			size_t *pl = sqrl_user_password_length( user );
			*pl = strlen( password );
			strcpy( (char*)ptr, password );
			if( SQRL_STATUS_OK == sqrl_user_load_with_password( user, storage, NULL, NULL )) {
				ptr = sqrl_user_key( user, KEY_MK );
				sodium_bin2hex( str, 512, ptr, 32 );
				printf( "  Decrypting w/ IMK: " );
				printInFours( str );
				ptr = sqrl_user_key( user, KEY_PIUK0 );
				printf( "  Decrypted:\n" );
				sodium_bin2hex( str, 512, ptr, 32 );
				printf( "    Decrypted PIUK0: " );
				printInFours( str );
				ptr = sqrl_user_key( user, KEY_PIUK1 );
				sodium_bin2hex( str, 512, ptr, 32 );
				printf( "    Decrypted PIUK1: " );
				printInFours( str );
				ptr = sqrl_user_key( user, KEY_PIUK2 );
				sodium_bin2hex( str, 512, ptr, 32 );
				printf( "    Decrypted PIUK2: " );
				printInFours( str );
				ptr = sqrl_user_key( user, KEY_PIUK3 );
				sodium_bin2hex( str, 512, ptr, 32 );
				printf( "    Decrypted PIUK3: " );
				printInFours( str );
			} else {
				printf( "  Decryption:        Failed\n" );
				return;
			}
		}
	} else {
		printf( "Block 2 Not found.\n" );
		return;
	}


}

int main( int argc, char *argv[] )
{
	sqrl_init();
	int i, l;
	Sqrl_Storage storage = NULL;

	for( i = 1; i < argc; i++ ) {
		if( 0 == strcmp( argv[i], "-h" ) ||
			0 == strcmp( argv[i], "-H" )) {
			printf( "%s", help );
			exit(0);
		}
		if( !password ) {
			password = argv[i];
			continue;
		}
		l = strlen( argv[i] );
		if( l == 24 ) {
			rc = argv[i];
			continue;
		}
		if( 0 == strncmp( argv[i], "SQRLDATA", 8 )) {
			text = argv[i];
			continue;
		}
		filename = argv[i];
	}
	if( text ) {
		storage = sqrl_storage_create();
		UT_string *sqrldata;
		utstring_new( sqrldata );
		utstring_printf( sqrldata, "%s", text );
		if( sqrl_storage_load_from_buffer( storage, sqrldata )) {
			printf( "Loaded text Identity:\n%s\n\n", utstring_body( sqrldata ));
		} else {
			printf( "Failed to load text Identity\n" );
			exit(1);
		}
		utstring_free( sqrldata );
	} else if( filename ) {
		storage = sqrl_storage_create();
		if( sqrl_storage_load_from_file( storage, filename )) {
			UT_string *sqrldata;
			utstring_new( sqrldata );
			sqrl_storage_save_to_buffer( storage, sqrldata, SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64 );
			printf( "Loaded file Identity:\n");
			printBreak( utstring_body( sqrldata ), 64 );
			utstring_free( sqrldata );
		} else {
			printf( "Failed to load Identity from file\n" );
			exit(1);
		}
	}
	if( storage ) {
		printBlock1( storage );
		printBlock2( storage );
		printBlock3( storage );
	} else {
		printf( "%s", help );
	}
	exit(0);
}