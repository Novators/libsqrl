/* makevectors.c  

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include "../sqrl_internal.h"

void enhash_vector(FILE *fp, uint8_t *input)
{
	uint8_t output[SQRL_KEY_SIZE];
	UT_string *buf;
	utstring_new( buf );

	Sqrl_EnHash( (uint64_t*)output, (uint64_t*)input );
	sqrl_b64u_encode(buf,input,SQRL_KEY_SIZE);
	sqrl_b64u_encode_append(buf,output,SQRL_KEY_SIZE);
	fwrite( utstring_body(buf), 1, utstring_len(buf), fp );
	fwrite( "\r\n", 1, 2, fp );
}

int main()
{
	sqrl_init();

	int i;
	FILE *fp = fopen( "vectors/enhash-vectors.txt", "wb" );
	if( !fp ) {
        printf( "Failed to open file: vectors/enhash-vectors.txt\n" );
		return -1;
	}
	uint8_t key[SQRL_KEY_SIZE];

	memset(key,0,SQRL_KEY_SIZE);
	enhash_vector(fp,key);

	memset(key,1,SQRL_KEY_SIZE);
	enhash_vector(fp,key);

	memset(key,0xFF,SQRL_KEY_SIZE);
	enhash_vector(fp,key);

	memset(key,0x55,SQRL_KEY_SIZE);
	enhash_vector(fp,key);

	memset(key,0xAA,SQRL_KEY_SIZE);
	enhash_vector(fp,key);

	for( i = 0; i < 995; i++ ) {
		randombytes_buf(key, SQRL_KEY_SIZE);
		enhash_vector( fp, key );
	}
	fclose(fp);

}