/** @file server_protocol.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include "sqrl_internal.h"

#define COMMAND_COUNT 5

static char commands[COMMAND_COUNT][8] = {
    "query", "ident", "disable", "enable", "remove"
};

static char context_kv_strings[CONTEXT_KV_COUNT][CONTEXT_KV_LENGTH+1] = { 
    "server", "client", "ids", "pids", "urs" 
};

static char client_kv_strings[CLIENT_KV_COUNT][CLIENT_KV_LENGTH+1] = { 
    "ver", "cmd", "opt", "btn", "idk", "pidk", "suk", "vuk"
};

static char server_kv_strings[SERVER_KV_COUNT][SERVER_KV_LENGTH+1] = {
    "ver", "nut", "tif", "qry", "suk", "ask", "url"
};

bool sqrl_server_verify_nut(
    Sqrl_Server_Context *context,
    uint32_t client_ip )
{
    if( !context ) return false;
    if( client_ip == context->nut.ip ) {
        FLAG_SET( context->tif, SQRL_TIF_IP_MATCH );
    }

    int64_t diff = sqrl_get_timestamp() - context->nut.timestamp;
    if( diff < 0 || diff > context->server->nut_expires ) {
        FLAG_SET( context->tif, SQRL_TIF_TRANSIENT_ERROR );
        return false;
    }
    return true;
}

bool sqrl_server_verify_server_string(
    Sqrl_Server_Context *context,
    uint32_t client_ip )
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
                if( sqrl_server_verify_nut( context, client_ip )) {
                    utstring_free( srv );
                    FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_SERVER_STRING );
                    return true;
                }
            }
        }
    }
    printf( "*** BAD SERVER STRING ***\n" );
    FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE | SQRL_TIF_CLIENT_FAILURE );
    utstring_free( srv );
    return false;
}

bool sqrl_server_parse_client( 
    Sqrl_Server_Context *context )
{
    if( !context ) return false;

    int found_keys = 0;
    int current_key = 0;
    int i;
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
                    free( context->client_strings[current_key] );
                }
                context->client_strings[current_key] = malloc( val_len + 1 );
                memcpy( context->client_strings[current_key], val, val_len );
                context->client_strings[current_key][val_len] = 0;
#if DEBUG_PRINT_SERVER_PROTOCOL
                //printf( "%10s: %s\n", client_kv_strings[current_key], context->client_strings[current_key] );
#endif
                found_keys |= (1<<current_key);
                break;
            }
        }
    }

    utstring_free( rStr );

    if( required_keys == (found_keys & required_keys) ) {
        for( i = 0; i < COMMAND_COUNT; i++ ) {
            if( 0 == strcmp( commands[i], context->client_strings[CLIENT_KV_CMD] )) {
                context->command = i;
                break;
            }
        }
        FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_CLIENT_STRING );
        return true;
    }
    FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE | SQRL_TIF_CLIENT_FAILURE );
    return false;
}

bool sqrl_server_verify_urs( Sqrl_Server_Context *context )
{
    if( !context ) return false;
    if( ! context->context_strings[CONTEXT_KV_URS] ) return false;
    if( ! context->user ) return false;
    bool retVal = false;
    UT_string *str, *sig;
    utstring_new( str );
    utstring_new( sig );
    utstring_printf( str, "%s%s", context->context_strings[CONTEXT_KV_CLIENT], context->context_strings[CONTEXT_KV_SERVER] );    
    sqrl_b64u_decode( sig, context->context_strings[CONTEXT_KV_URS], strlen( context->context_strings[CONTEXT_KV_URS]));

    if( sqrl_verify_sig( str, (uint8_t*)utstring_body( sig ), context->user->vuk )) {
        FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_URS );
        retVal = true;
    }
    utstring_free( str );
    utstring_free( sig );
    return retVal;
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
        utstring_printf( str, "%s%s", context->context_strings[CONTEXT_KV_CLIENT], context->context_strings[CONTEXT_KV_SERVER] );
        if( context->context_strings[CONTEXT_KV_IDS] ) {
            sqrl_b64u_decode( sig, context->context_strings[CONTEXT_KV_IDS], strlen( context->context_strings[CONTEXT_KV_IDS] ));
            sqrl_b64u_decode( key, context->client_strings[CLIENT_KV_IDK], strlen( context->client_strings[CLIENT_KV_IDK] ));
            if( !sqrl_verify_sig( str, (uint8_t*)utstring_body( sig ), (uint8_t*)utstring_body( key ))) {
                utstring_free( str );
                utstring_free( key );
                utstring_free( sig );
                printf( "IDS FAILURE\n" );
                FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE | SQRL_TIF_CLIENT_FAILURE );
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
                printf( "PIDS FAILURE\n" );
                FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE | SQRL_TIF_CLIENT_FAILURE );
                return false;
            }
            FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_PIDS );
        }
        utstring_free( str );
        utstring_free( key );
        utstring_free( sig );
        return true;
    }
    FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE | SQRL_TIF_CLIENT_FAILURE );
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
    uint32_t client_ip,
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
                //printf( "%10s: %s\n", context_kv_strings[current_key], context->context_strings[current_key] );
#endif                
                found_keys |= (1<<current_key);
                break;
            }
        }
    }

    utstring_free( rStr );

    if( required_keys == (found_keys & required_keys) ) {
        if( sqrl_server_verify_server_string( context, client_ip )) {
            if( sqrl_server_verify_signatures( context )) {
                FLAG_SET( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY );
            }
        }
    }
}

bool sqrl_server_get_user( 
    Sqrl_Server_Context *context,
    char *idk )
{
    char *blob = malloc( 512 );
    sqrl_scb_user *onUserOp = (sqrl_scb_user*)context->server->onUserOp;
    if( (onUserOp)( 
        SQRL_SCB_USER_FIND,
        context->server->uri->host,
        idk,
        NULL,
        blob )) 
    {
        UT_string *tmp;
        utstring_new( tmp );
        sqrl_b64u_decode( tmp, blob, strlen( blob ));
        if( context->user ) free( context->user );
        context->user = malloc( sizeof( Sqrl_Server_User ));
        memcpy( context->user, utstring_body( tmp ), utstring_len( tmp ));
        utstring_free( tmp );
        free( blob );
        if( FLAG_CHECK( context->user->flags, SQRL_SERVER_USER_FLAG_DISABLED )) {
            FLAG_SET( context->tif, SQRL_TIF_SQRL_DISABLED );
        }
        return true;
    }
    free( blob );
    return false;
}

void sqrl_server_add_user_suk( Sqrl_Server_Context *context )
{
    if( !context ) return;
    if( !context->user ) return;
    if( context->server_strings[ SERVER_KV_SUK ]) return;
    UT_string *tmp;
    utstring_new( tmp );
    sqrl_b64u_encode( tmp, context->user->suk, SQRL_KEY_SIZE );
    context->server_strings[SERVER_KV_SUK] = malloc( 1 + utstring_len( tmp ));
    strcpy( context->server_strings[SERVER_KV_SUK], utstring_body( tmp ));
    utstring_free( tmp );
}

DLL_PUBLIC
void sqrl_server_handle_query(
    Sqrl_Server_Context *context,
    uint32_t client_ip,
    const char *query,
    size_t query_len )
{
    if( !context || !query ) return;
    sqrl_scb_user *onUserOp = (sqrl_scb_user*)context->server->onUserOp;

    UT_string *reply, *tmp;
    utstring_new( reply );
    sqrl_server_parse_query( context, client_ip, query, query_len );
    if( !FLAG_CHECK( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY )) {
        FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE );
        goto REPLY;
    }
    if( sqrl_server_get_user( context, context->client_strings[CLIENT_KV_IDK])) {
        FLAG_SET( context->tif, SQRL_TIF_ID_MATCH );
        if( context->command == SQRL_CMD_ENABLE ||
            context->command == SQRL_CMD_REMOVE ) {
            if( !sqrl_server_verify_urs( context )) {
                FLAG_CLEAR( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY );
                FLAG_SET( context->tif, SQRL_TIF_CLIENT_FAILURE );
            }
        }
    } else {
        if( context->client_strings[CLIENT_KV_PIDK] ) {
            if( sqrl_server_get_user( context, context->client_strings[CLIENT_KV_PIDK])) {
                FLAG_SET( context->tif, SQRL_TIF_PREVIOUS_ID_MATCH );
                sqrl_server_add_user_suk( context );
                if( context->context_strings[CONTEXT_KV_URS] ) {
                    if( ! sqrl_server_verify_urs( context )) {
                        FLAG_CLEAR( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY );
                        FLAG_SET( context->tif, SQRL_TIF_CLIENT_FAILURE );
                    }
                }
            }
        }
    }
    if( !FLAG_CHECK( context->flags, SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY )) {
        FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE );
        goto REPLY;
    }
    if( context->user ) {
        if( FLAG_CHECK( context->user->flags, SQRL_SERVER_USER_FLAG_DISABLED )) {
            FLAG_SET( context->tif, SQRL_TIF_SQRL_DISABLED );
        }
    }
    if( FLAG_CHECK( context->tif, SQRL_TIF_SQRL_DISABLED )) {
        sqrl_server_add_user_suk( context );
    }

    switch( context->command ) {
    case SQRL_CMD_QUERY:
        goto REPLY;
    case SQRL_CMD_REMOVE:
        if( (onUserOp)(SQRL_SCB_USER_DELETE,
            context->server->uri->host,
            context->client_strings[CLIENT_KV_IDK],
            NULL, NULL )) {
            FLAG_CLEAR( context->tif, SQRL_TIF_ID_MATCH );
            FLAG_CLEAR( context->tif, SQRL_TIF_PREVIOUS_ID_MATCH );
            goto REPLY;
        }
        FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE );
        break;
    case SQRL_CMD_ENABLE:
        if( FLAG_CHECK( context->tif, SQRL_TIF_ID_MATCH )) {
            FLAG_CLEAR( context->user->flags, SQRL_SERVER_USER_FLAG_DISABLED );
            utstring_new( tmp );
            sqrl_b64u_encode( tmp, (uint8_t*)context->user, sizeof( Sqrl_Server_User ));

            if( (onUserOp)(SQRL_SCB_USER_UPDATE,
                context->server->uri->host,
                context->client_strings[CLIENT_KV_IDK],
                NULL, utstring_body( tmp ))) {
                FLAG_CLEAR( context->tif, SQRL_TIF_SQRL_DISABLED );
                utstring_free( tmp );
                goto REPLY;
            }
            utstring_free( tmp );
        } else if( FLAG_CHECK( context->tif, SQRL_TIF_PREVIOUS_ID_MATCH )) {
            FLAG_CLEAR( context->user->flags, SQRL_SERVER_USER_FLAG_DISABLED );

            utstring_new( tmp );
            sqrl_b64u_encode( tmp, (uint8_t*)context->user, sizeof( Sqrl_Server_User ));
            if( (onUserOp)(SQRL_SCB_USER_REKEYED,
                context->server->uri->host,
                context->client_strings[CLIENT_KV_IDK],
                context->client_strings[CLIENT_KV_PIDK],
                utstring_body( tmp ))) {
                utstring_free( tmp );
                FLAG_CLEAR( context->tif, SQRL_TIF_SQRL_DISABLED );
                FLAG_CLEAR( context->tif, SQRL_TIF_PREVIOUS_ID_MATCH );
                FLAG_SET( context->tif, SQRL_TIF_ID_MATCH );
                goto REPLY;
            }
            utstring_free( tmp );
        }
        FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE );
        break;
    case SQRL_CMD_DISABLE:
        if( FLAG_CHECK( context->tif, SQRL_TIF_ID_MATCH )) {
            FLAG_SET( context->user->flags, SQRL_SERVER_USER_FLAG_DISABLED );
            utstring_new( tmp );
            sqrl_b64u_encode( tmp, (uint8_t*)context->user, sizeof( Sqrl_Server_User ));

            if( (onUserOp)(SQRL_SCB_USER_UPDATE,
                context->server->uri->host,
                context->client_strings[CLIENT_KV_IDK],
                NULL, utstring_body( tmp ))) {
                FLAG_SET( context->tif, SQRL_TIF_SQRL_DISABLED );
                utstring_free( tmp );
                goto REPLY;
            }
            utstring_free( tmp );
        }
        FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE );
        break;
    case SQRL_CMD_IDENT:
        if( FLAG_CHECK( context->tif, SQRL_TIF_ID_MATCH )) {
            if( FLAG_CHECK( context->tif, SQRL_TIF_SQRL_DISABLED )) {
                FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE );
                break;
            }
            (onUserOp)(SQRL_SCB_USER_IDENTIFIED,
                context->server->uri->host,
                context->client_strings[CLIENT_KV_IDK],
                NULL, NULL );
        } else if( FLAG_CHECK( context->tif, SQRL_TIF_PREVIOUS_ID_MATCH )) {
            if( FLAG_CHECK( context->tif, SQRL_TIF_SQRL_DISABLED )) {
                FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE );
                break;
            }
            utstring_new( tmp );
            sqrl_b64u_decode( tmp, context->client_strings[CLIENT_KV_SUK], strlen( context->client_strings[CLIENT_KV_SUK]));
            memcpy( context->user->suk, utstring_body( tmp ), SQRL_KEY_SIZE);
            sqrl_b64u_decode( tmp, context->client_strings[CLIENT_KV_VUK], strlen( context->client_strings[CLIENT_KV_VUK]));
            memcpy( context->user->vuk, utstring_body( tmp ), SQRL_KEY_SIZE);
            sqrl_b64u_decode( tmp, context->client_strings[CLIENT_KV_IDK], strlen( context->client_strings[CLIENT_KV_IDK]));
            memcpy( context->user->idk, utstring_body( tmp ), SQRL_KEY_SIZE);
            sqrl_b64u_encode( tmp, (uint8_t*)context->user, sizeof( Sqrl_Server_User ));
            (onUserOp)(SQRL_SCB_USER_REKEYED,
                context->server->uri->host,
                context->client_strings[CLIENT_KV_IDK],
                context->client_strings[CLIENT_KV_PIDK],
                utstring_body( tmp ));
            utstring_free( tmp );
            FLAG_CLEAR( context->tif, SQRL_TIF_PREVIOUS_ID_MATCH );
            FLAG_SET( context->tif, SQRL_TIF_ID_MATCH );
            (onUserOp)(SQRL_SCB_USER_IDENTIFIED,
                context->server->uri->host,
                context->client_strings[CLIENT_KV_IDK],
                NULL, NULL );
        } else {
            if( context->client_strings[CLIENT_KV_IDK] &&
                context->client_strings[CLIENT_KV_SUK] &&
                context->client_strings[CLIENT_KV_VUK] ) {
                // Create user
                if( !context->user ) context->user = malloc( sizeof( Sqrl_Server_User ));
                context->user->flags = 0; 
                utstring_new( tmp );
                sqrl_b64u_decode( tmp, context->client_strings[CLIENT_KV_IDK], strlen( context->client_strings[CLIENT_KV_IDK]));
                memcpy( &context->user->idk, utstring_body( tmp ), SQRL_KEY_SIZE );
                sqrl_b64u_decode( tmp, context->client_strings[CLIENT_KV_SUK], strlen( context->client_strings[CLIENT_KV_SUK]));
                memcpy( &context->user->suk, utstring_body( tmp ), SQRL_KEY_SIZE );
                sqrl_b64u_decode( tmp, context->client_strings[CLIENT_KV_VUK], strlen( context->client_strings[CLIENT_KV_VUK]));
                memcpy( &context->user->vuk, utstring_body( tmp ), SQRL_KEY_SIZE );
                sqrl_b64u_encode( tmp, (uint8_t*)context->user, sizeof( Sqrl_Server_User ));
                if( (onUserOp)( SQRL_SCB_USER_CREATE,
                    context->server->uri->host,
                    context->client_strings[CLIENT_KV_IDK],
                    NULL, utstring_body( tmp ))) {
                    (onUserOp)(SQRL_SCB_USER_IDENTIFIED,
                        context->server->uri->host,
                        context->client_strings[CLIENT_KV_IDK],
                        NULL, NULL );
                    FLAG_SET( context->tif, SQRL_TIF_ID_MATCH );
                    utstring_free( tmp );
                    goto REPLY;
                }
                utstring_free( tmp );
            }
            FLAG_SET( context->tif, SQRL_TIF_COMMAND_FAILURE );
        }
        break;
    default:
        FLAG_SET( context->tif, SQRL_TIF_FUNCTION_NOT_SUPPORTED );
        goto REPLY;
    }

REPLY:
    sqrl_server_build_reply( context, reply );
    sqrl_scb_send *onSend = (sqrl_scb_send*)context->server->onSend;
    (onSend)( context, utstring_body( reply ), utstring_len( reply ));

DONE:
    utstring_free( reply );
}


