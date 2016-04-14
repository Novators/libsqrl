/** @file server_protocol.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include "sqrl_internal.h"

static char context_kv_strings[CONTEXT_KV_COUNT][CONTEXT_KV_LENGTH+1] = { 
    "server", "client", "ids", "pids", "urs" 
};

static char client_kv_strings[CLIENT_KV_COUNT][CLIENT_KV_LENGTH+1] = { 
    "ver", "cmd", "opt", "btn", "idk", "pidk", "suk", "vuk"
};

static char server_kv_strings[SERVER_KV_COUNT][SERVER_KV_LENGTH+1] = {
    "ver", "nut", "tif", "qry", "suk", "ask", "url"
};

bool sqrl_server_verify_server_string(
    Sqrl_Server_Context *context )
{
    if( !context ) return false;
    UT_string *srv;
    utstring_new( srv );
    sqrl_b64u_decode( srv, context->context_strings[CONTEXT_KV_SERVER], strlen( context->context_strings[CONTEXT_KV_SERVER ]));
    if( sqrl_server_verify_mac( context->server, srv )) {
        char *p, *pp;
        p = strstr( utstring_body( srv ), "nut=" );
        if( p ) {
            p += 4;
            pp = strchr( p, '&' );
            size_t len;
            if( pp ) {
                len = pp - p;
            } else {
                len = strlen( p );
            }
            UT_string *t;
            utstring_new( t );
            sqrl_b64u_decode( t, p, len );
            memcpy( &context->nut, utstring_body( t ), sizeof( Sqrl_Nut ));
            utstring_free( t );
            if( sqrl_server_nut_decrypt( context->server, &context->nut )) {
                utstring_free( srv );
                FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_SERVER_STRING );
                return true;
            }
        }
    }
    utstring_free( srv );
    return false;
}

bool sqrl_server_parse_client( 
    Sqrl_Server_Context *context )
{
    if( !context ) return false;

    int found_keys = 0;
    int current_key = 0;
    uint16_t required_keys =
        (1<<CLIENT_KV_VER) |
        (1<<CLIENT_KV_CMD) |
        (1<<CLIENT_KV_IDK);

    UT_string *rStr;

    FLAG_CLEAR( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY );

    utstring_new( rStr );
    sqrl_b64u_decode( rStr, context->context_strings[CONTEXT_KV_CLIENT], strlen( context->context_strings[CONTEXT_KV_CLIENT]));

    size_t key_len, val_len;
    char *str, *key, *val;
    str = utstring_body( rStr );

    while( sqrl_parse_key_value( &str, &key, &val, &key_len, &val_len, "\r\n" )) {
        for( current_key = 0; current_key < CLIENT_KV_COUNT; current_key++ ) {
            if( 0 == strncmp( key, client_kv_strings[current_key], key_len )) {
                if( context->client_strings[current_key] ) {
                    free( context->context_strings[current_key] );
                }
                context->client_strings[current_key] = malloc( val_len + 1 );
                memcpy( context->client_strings[current_key], val, val_len );
                context->client_strings[current_key][val_len] = 0;
#if DEBUG_PRINT_SERVER_PROTOCOL
                printf( "%10s: %s\n", client_kv_strings[current_key], context->client_strings[current_key] );
#endif
                found_keys |= (1<<current_key);
                break;
            }
        }
    }

    utstring_free( rStr );

    if( required_keys == (found_keys & required_keys) ) {
        FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_CLIENT_STRING );
        return true;
    }
    return false;
}

bool sqrl_server_verify_signatures(
    Sqrl_Server_Context *context )
{
    if( !context ) return false;
    if( sqrl_server_parse_client( context )) {
        UT_string *str, *key, *sig;
        utstring_new( str );
        utstring_new( key );
        utstring_new( sig );
#if DEBUG_PRINT_SERVER_PROTOCOL
        utstring_printf( str, "%s%s", context->context_strings[CONTEXT_KV_CLIENT], context->context_strings[CONTEXT_KV_SERVER] );
#endif
        if( context->context_strings[CONTEXT_KV_IDS] ) {
            sqrl_b64u_decode( sig, context->context_strings[CONTEXT_KV_IDS], strlen( context->context_strings[CONTEXT_KV_IDS] ));
            sqrl_b64u_decode( key, context->client_strings[CLIENT_KV_IDK], strlen( context->client_strings[CLIENT_KV_IDK] ));
            if( !sqrl_verify_sig( str, (uint8_t*)utstring_body( sig ), (uint8_t*)utstring_body( key ))) {
                utstring_free( str );
                utstring_free( key );
                utstring_free( sig );
                return false;
            }
            FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_IDS );
        }
        if( context->context_strings[CONTEXT_KV_PIDS] ) {
            sqrl_b64u_decode( sig, context->context_strings[CONTEXT_KV_PIDS], strlen( context->context_strings[CONTEXT_KV_PIDS] ));
            sqrl_b64u_decode( key, context->client_strings[CLIENT_KV_PIDK], strlen( context->client_strings[CLIENT_KV_PIDK] ));
            if( !sqrl_verify_sig( str, (uint8_t*)utstring_body( sig ), (uint8_t*)utstring_body( key ))) {
                utstring_free( str );
                utstring_free( key );
                utstring_free( sig );
                return false;
            }
            FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_PIDS );
        }
        if( context->context_strings[CONTEXT_KV_URS] ) {
            sqrl_b64u_decode( sig, context->context_strings[CONTEXT_KV_URS], strlen( context->context_strings[CONTEXT_KV_URS] ));
            sqrl_b64u_decode( key, context->client_strings[CLIENT_KV_SUK], strlen( context->client_strings[CLIENT_KV_SUK] ));
            if( !sqrl_verify_sig( str, (uint8_t*)utstring_body( sig ), (uint8_t*)utstring_body( key ))) {
                utstring_free( str );
                utstring_free( key );
                utstring_free( sig );
                return false;
            }
            FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_URS );
        }
        utstring_free( str );
        utstring_free( key );
        utstring_free( sig );
        return true;
    }
    return false;
}

bool sqrl_server_build_reply( Sqrl_Server_Context *context, UT_string *reply )
{
    if( !context || !reply ) return false;
    utstring_renew( reply );
    utstring_printf( reply, "ver=%s\r\n", SQRL_VERSION_STRING );
    uint32_t ip = context->nut.ip; // Reuse original IP address
    sqrl_server_nut_generate( context->server, &context->nut, ip );
    utstring_printf( reply, "nut=" );
    sqrl_b64u_encode_append( reply, (unsigned char*)&context->nut, sizeof( Sqrl_Nut ));
    utstring_printf( reply, "\r\n" );
    utstring_printf( reply, "tif=%X\r\n", context->tif );
    if( !context->server_strings[SERVER_KV_QRY] ) {
        size_t len = strlen( context->server->uri->prefix );
        char *p, *pp;
        p = context->server->uri->challenge + len - 1;
        pp = strchr( p, '?' );
        if( pp ) {
            len = pp - p;
        } else {
            len = strlen( p );
        }
        context->server_strings[SERVER_KV_QRY] = calloc( 1, len + 1 );
        memcpy( context->server_strings[SERVER_KV_QRY], p, len );
    }
    utstring_printf( reply, "qry=%s\r\n", context->server_strings[SERVER_KV_QRY] );
    if( context->server_strings[SERVER_KV_SUK] ) {
        utstring_printf( reply, "suk=%s\r\n", context->server_strings[SERVER_KV_SUK] );
    }
    if( context->server_strings[SERVER_KV_ASK] ) {
        utstring_printf( reply, "ask=%s\r\n", context->server_strings[SERVER_KV_ASK] );
    }
    if( context->server_strings[SERVER_KV_URL] ) {
        utstring_printf( reply, "url=%s\r\n", context->server_strings[SERVER_KV_URL] );
    }
    sqrl_server_add_mac( context->server, reply, 0 );
    return true;
}

void sqrl_server_parse_query( 
    Sqrl_Server_Context *context, 
    const char *query, 
    size_t query_len )
{
    if( !context || !query || query_len == 0 ) return;
    int found_keys = 0;
    int current_key = 0;
    uint16_t required_keys =
        (1<<CONTEXT_KV_SERVER) |
        (1<<CONTEXT_KV_CLIENT) |
        (1<<CONTEXT_KV_IDS); 

    char *str, *key, *val;
    size_t key_len, val_len;
    UT_string *rStr;

    FLAG_CLEAR( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY );

    utstring_new( rStr );
    utstring_bincpy( rStr, query, query_len );

    str = utstring_body( rStr );

    while( sqrl_parse_key_value( &str, &key, &val, &key_len, &val_len, "&" )) {
        for( current_key = 0; current_key < CONTEXT_KV_COUNT; current_key++ ) {
            if( strncmp( key, context_kv_strings[current_key], strlen( context_kv_strings[current_key]) ) == 0 ) {
                if( context->context_strings[current_key] ) {
                    free( context->context_strings[current_key] );
                }
                context->context_strings[current_key] = malloc( val_len + 1 );
                memcpy( context->context_strings[current_key], val, val_len );
                context->context_strings[current_key][val_len] = 0;
#if DEBUG_PRINT_SERVER_PROTOCOL
                printf( "%10s: %s\n", context_kv_strings[current_key], context->context_strings[current_key] );
#endif                
                found_keys |= (1<<current_key);
                break;
            }
        }
    }

    utstring_free( rStr );

    if( required_keys == (found_keys & required_keys) ) {
        if( sqrl_server_verify_server_string( context )) {
            if( sqrl_server_verify_signatures( context )) {
                UT_string *reply;
                utstring_new( reply );
                sqrl_server_build_reply( context, reply );
                printf( "%10s: %s\n", "REPLY", utstring_body( reply ));
                utstring_free( reply );
                FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY );
            }
        }
    }
}

