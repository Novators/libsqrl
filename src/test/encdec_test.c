/* encdec_text.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include <stdio.h>
#include "../sqrl_client.h"

#define NT 10

const size_t inSize[NT] = { 0,1,2,3,4,5,6,3,3,6 };
const char *inVector[NT] = {
  "",
  "f",
  "fo",
  "foo",
  "foob",
  "fooba",
  "foobar",
  "\x49\x00\x02",
  "\x00\x08\xa4",
  "\x49\x00\x02\x00\x08\xa4"};


const char *b56id = "bMayn ykbH7 ee56M cJVfn\nzqmCC iMw3i u6hbM C9JiW\nLyMKK iYnAF F5Ygf sw6wx\n2hUb9 W8B7b AW4zb dsfcv\nhYidG rwviE bRxLr daZwB\n5iMXV 5F ";
const char *b56id_bad = "bMayn ykbH7 ee56M cJVfn\nzqmCC iMw3i u6hbM C9JiW\nLyMKK iYnAF __BAD__ F5Ygf sw6wx\n2hUb9 W8B7b AW4zb dsfcv\nhYidG rwviE bRxLr daZwB\n5iMXV 5F";

bool testbase56check()
{
  bool result = true;
  UT_string *tmp, *decoded;
  utstring_new( tmp );
  utstring_new( decoded );

  size_t validated;
  
  validated = sqrl_b56c_validate( tmp, b56id_bad, strlen( b56id_bad ), true);
  if( validated == 47 ) {
    printf( "\nValidate b56id_bad: \n%s\nPASS\n", utstring_body( tmp ));
  } else {
    printf( "\nValidate b56id_bad: \n%s\nFAIL\n", utstring_body( tmp ));
    result = false;
  }

  validated = sqrl_b56c_validate( tmp, b56id, strlen( b56id ), true );
  printf( "Validate and format:\n%s\n", utstring_body( tmp ));
  if( validated == strlen( b56id )) {
    printf( "Validate b56id (%zu of %zu): PASS\n", validated, strlen( b56id ));
  } else {
    printf( "Validate b56id (%zu of %zu): FAIL\n", validated, strlen( b56id ));
    result = false;
  }

  sqrl_b56c_decode( tmp, b56id, strlen( b56id ));

  sqrl_b56c_encode( decoded, utstring_body( tmp ), utstring_len( tmp ));
  *(char*)(utstring_body( decoded ) + utstring_len( decoded ) - 1) = ' ';
  printf( "(re)Encoded:\n%s\n", utstring_body( decoded ));
  if( strcmp( utstring_body( decoded ), b56id ) == 0 ) {
    printf( "(re)Encoded matches source\n" );
  } else {
    printf( "(re)Encoding mismatch!\n" );
    result = false;
  }
  
  utstring_free( tmp );
  utstring_free( decoded );
  return result;
}

bool testbase56()
{
  bool result = true;
  const char *dvector[NT] = {
    "",
    "q3",
    "G7B",
    "ykaj2",
    "yksvz4",
    "Q8SEUZF",
    "y4MpRmpJ3",
    "tpj22",
    "SvD73",
    "KBtX9tRs3"};
  UT_string *s = NULL;
  int i;
  
  for( i = 0; i < NT; i++ ) {
    printf( "%s\n", dvector[i] );
    s = sqrl_b56_encode( s, (uint8_t*)inVector[i], inSize[i] );
    if( utstring_len(s) != strlen( dvector[i] ) ||
	strcmp( utstring_body(s), dvector[i] )) {
      printf( "ENCODE ERROR (%d): %s\n", i, utstring_body(s) );
      result = false;
    }
    utstring_free( s );
    s = sqrl_b56_decode( NULL, dvector[i], strlen( dvector[i] ));
    if( utstring_len(s) != inSize[i] ||
	memcmp( utstring_body(s), inVector[i], inSize[i] )) {
      printf( "DECODE ERROR (%d): %s\n", i, utstring_body(s) );
      result = false;
    }
    
  }
  
  utstring_free(s);
  return result;
}

bool testbase64()
{
  bool result = true;
  const char *dvector[NT] = {
    "",
    "Zg",
    "Zm8",
    "Zm9v",
    "Zm9vYg",
    "Zm9vYmE",
    "Zm9vYmFy",
    "SQAC",
    "AAik",
    "SQACAAik"};
  UT_string *s = NULL;
  int i;
  
  for( i = 0; i < NT; i++ ) {
    printf( "%s\n", dvector[i] );
    s = sqrl_b64u_encode( s, (uint8_t*)inVector[i], inSize[i] );
    if( utstring_len(s) != strlen( dvector[i] ) ||
	strcmp( utstring_body(s), dvector[i] )) {
      printf( "ENCODE ERROR (%d): %s\n", i, utstring_body(s) );
      result = false;
    }
    utstring_free( s );
    s = sqrl_b64u_decode( NULL, dvector[i], strlen( dvector[i] ));
    if( s == NULL ) {
		printf( "s is NULL.\n" );
	}
    if( utstring_len(s) != inSize[i] ||
	memcmp( utstring_body(s), inVector[i], inSize[i] )) {
      printf( "DECODE ERROR (%d): %s\n", i, utstring_body(s) );
      result = false;
    }
  }
  
  utstring_free(s);
  return result;
}


int main (int argc, char **argv)
{
  bool result = true;
  if( result ) result = testbase64();
  if( result ) result = testbase56();
  if( result ) result = testbase56check();
  if( result ) exit(0);
  exit(1);
}
