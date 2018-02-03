/* server_test.c

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_internal.h"

char host[] = "sqrlid.com";

int main()
{
    UT_string *str;
    utstring_new( str );
    char buf[128];

    sqrl_init();

    Sqrl_Server *server = sqrl_server_create(
        "sqrl://sqrlid.com/auth.php?nut=_LIBSQRL_NUT_",
        "I am SQRLid!", 12,
        NULL, NULL, 1 );
    if( !server ) {
        printf( "Failed to create server\n" );
        exit(1);
    }
    printf( "host: %s\n", server->uri->host );
    printf( "url:  %s\n", server->uri->url );
    printf( "chal: %s\n", server->uri->challenge );

    printf( "Nut Len: %lu\n", sizeof( Sqrl_Nut ));

    Sqrl_Nut nut;
    if( ! sqrl_server_nut_generate( server, &nut, 0)) {
        printf( "Nut Generation Failed\n" );
        exit(1);
    }
    sqrl_b64u_encode( str, (uint8_t*)&nut, sizeof( Sqrl_Nut ));
    printf( "Encrypted NUT: %s\n", utstring_body( str ));

    if( ! sqrl_server_nut_decrypt( server, &nut )) {
        sodium_bin2hex( buf, 128, (unsigned char*)&nut, sizeof( Sqrl_Nut ));
        printf( "Decrypted NUT: %s\n", buf );
        printf( "Nut Validation Failed\n" );
        exit(1);
    }
    sodium_bin2hex( buf, 128, (unsigned char*)&nut, sizeof( Sqrl_Nut ));
    printf( "Decrypted NUT: %s\n", buf );

    char *lnk = sqrl_server_create_link( server, 0 );
    if( lnk ) {
        printf( "Link: %s\n", lnk );
    } else {
        printf( "Failed to create link\n" );
        exit(1);
    }
    free( lnk );

    sqrl_server_destroy( server );
    exit( sqrl_stop() );
}
