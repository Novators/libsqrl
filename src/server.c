/** @file server.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include "sqrl_internal.h"
#include "crypto/aes.h"

bool sqrl_server_init( 
    Sqrl_Server *server,
    char *uri,
    char *sfn,
    char *passcode,
    size_t passcode_len,
    int nut_life )
{
    if( !server ) return false;
    memset( server, 0, sizeof( Sqrl_Server ));

    if( sfn ) {
        server->sfn = malloc( strlen( sfn ) + 1 );
        strcpy( server->sfn, sfn );
    } else {
        Sqrl_Uri *tmpUri = sqrl_uri_parse( uri );
        if( tmpUri ) {
            server->sfn = malloc( strlen( tmpUri->host ) + 1 );
            strcpy( server->sfn, tmpUri->host );
        }
        tmpUri = sqrl_uri_free( tmpUri );
    }

    if( uri ) {
        UT_string *str;
        utstring_new( str );
        char *p, *pp;
        p = strstr( uri, SQRL_SERVER_TOKEN_SFN );
        if( p ) {
            utstring_bincpy( str, uri, p - uri );
            sqrl_b64u_encode_append( str, (uint8_t*)server->sfn, strlen( server->sfn ));
            pp = p + strlen( SQRL_SERVER_TOKEN_SFN );
            utstring_printf( str, "%s", pp );
            server->uri = sqrl_uri_parse( utstring_body( str ));
            utstring_free( str );
        } else {
            server->uri = sqrl_uri_parse( uri );
        }
        if( ! server->uri ) {
            sqrl_server_clear( server );
            return false;
        }
    } else {
        return false;
    }

    if( passcode ) {
        crypto_hash_sha256( server->key, (unsigned char*)passcode, passcode_len );
    } else {
        randombytes_buf( server->key, 32 );
    }

    server->nut_expires = nut_life * 1000000;
    return true;
}

void sqrl_server_clear( Sqrl_Server *server )
{
    if( !server ) return;
    if( server->uri ) server->uri = sqrl_uri_free( server->uri );
    if( server->sfn ) free( server->sfn );
    sodium_memzero( server, sizeof( Sqrl_Server ));
}

Sqrl_Server *sqrl_server_create(
    char *uri,
    char *sfn,
    char *passcode,
    size_t passcode_len,
    int nut_life )
{
    Sqrl_Server *srv = malloc( sizeof( Sqrl_Server ));
    if( ! sqrl_server_init( srv, uri, sfn, passcode, passcode_len, nut_life )) {
        free( srv );
        srv = NULL;
    }
    return srv;
}

Sqrl_Server *sqrl_server_destroy( Sqrl_Server *server )
{
    if( !server ) return NULL;
    sqrl_server_clear( server );
    free( server );
    return NULL;
}

bool sqrl_server_nut_generate( 
    Sqrl_Server *server,
    Sqrl_Nut *nut, 
    uint32_t ip )
{
    if( !server ) return false;
    if( !nut ) return false;
    Sqrl_Nut pt;
    pt.ip = ip;
    pt.timestamp = sqrl_get_timestamp();
    pt.random = randombytes_random();

    aes_context ctx;
    if( 0 != aes_setkey( &ctx, ENCRYPT, server->key, 16 )) {
        return false;
    }
    if( 0 != aes_cipher( &ctx, (unsigned char*)&pt, (unsigned char*)nut )) {
        sodium_memzero( &ctx, sizeof( aes_context ));
        return false;
    }
    sodium_memzero( &ctx, sizeof( aes_context ));
    return true;
}

bool sqrl_server_nut_decrypt(
    Sqrl_Server *server,
    Sqrl_Nut *nut )
{
    if( !server ) return false;
    if( !nut ) return false;
    Sqrl_Nut pt;
    memset( &pt, 0, sizeof( Sqrl_Nut ));

    aes_context ctx;
    if( 0 != aes_setkey( &ctx, DECRYPT, server->key, 16 )) {
        return false;
    }
    if( 0 != aes_cipher( &ctx, (unsigned char*)nut, (unsigned char*)&pt )) {
        sodium_memzero( &ctx, sizeof( aes_context ));
        return false;
    }
    sodium_memzero( &ctx, sizeof( aes_context ));

    int64_t diff = sqrl_get_timestamp() - pt.timestamp;
    if( diff < 0 || diff > server->nut_expires ) {
        // Stale Nut
        return false;
    }

    memcpy( nut, &pt, sizeof( Sqrl_Nut ));
    return true;
}

void sqrl_server_add_mac( Sqrl_Server *server, UT_string *str )
{
    if( !server || !str ) return;
    uint8_t mac[crypto_auth_BYTES];
    crypto_auth( mac, (unsigned char*)utstring_body( str ), utstring_len( str ), server->key );
    utstring_printf( str, "&mac=" );
    sqrl_b64u_encode_append( str, mac, SQRL_SERVER_MAC_LENGTH );
}

bool sqrl_server_verify_mac( Sqrl_Server *server, UT_string *str ) 
{
    if( !server || !str ) return false;
    char *m = strstr( utstring_body( str ), "&mac=" );
    size_t len = 0;
    if( m ) {
        len = m - utstring_body( str );
        m += 5;
        uint8_t mac[crypto_auth_BYTES];
        crypto_auth( mac, (unsigned char*)utstring_body(str), len, server->key );
        UT_string *v;
        utstring_new( v );
        sqrl_b64u_decode( v, m, strlen( m ));
        if( 0 == memcmp( mac, utstring_body(v), SQRL_SERVER_MAC_LENGTH )) {
            utstring_free( v );
            return true;
        }
    }
    return false;
}

char *sqrl_server_create_link( Sqrl_Server *server, uint32_t ip )
{
    if( !server ) return false;
    char *retVal = NULL;
    Sqrl_Nut nut;
    if( sqrl_server_nut_generate( server, &nut, ip )) {
        char *p, *pp;
        p = strstr( server->uri->challenge, SQRL_SERVER_TOKEN_NUT );
        if( p ) {
            UT_string *str;
            utstring_new( str );
            utstring_bincpy( str, server->uri->challenge, p - server->uri->challenge );
            sqrl_b64u_encode_append( str, (uint8_t*)&nut, sizeof( Sqrl_Nut ));
            pp = p + strlen( SQRL_SERVER_TOKEN_NUT );
            utstring_printf( str, "%s", pp );
            sqrl_server_add_mac( server, str );
            retVal = malloc( utstring_len( str ) + 1 );
            strcpy( retVal, utstring_body( str ));
            utstring_free( str );
        }
    }
    return retVal;
}

Sqrl_Server_Context *sqrl_server_context_create( Sqrl_Server *server )
{
    if( !server ) return NULL;
    Sqrl_Server_Context *ctx = calloc( 1, sizeof( Sqrl_Server_Context ));
    ctx->server = server;
    return ctx;
}

Sqrl_Server_Context *sqrl_server_context_destroy( Sqrl_Server_Context *ctx )
{
    if( !ctx ) return NULL;
    if( ctx->user ) free( ctx->user );
    int i;
    for( i = 0; i < CONTEXT_KV_COUNT; i++ ) {
        if( ctx->context_strings[i] ) 
            free( ctx->context_strings[i] );
    }
    for( i = 0; i < CLIENT_KV_COUNT; i++ ) {
        if( ctx->client_strings[i] )
            free( ctx->client_strings[i] );
    }
    free( ctx );
    return NULL;
}
