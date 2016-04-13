/** @file sqrl_client.h 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/  
#ifndef SQRL_SERVER_H_INCLUDED
#define SQRL_SERVER_H_INCLUDED

#include "sqrl_common.h"

#define SQRL_SERVER_MAC_LENGTH 16
#define SQRL_SERVER_TOKEN_SFN "_LIBSQRL_SFN_"
#define SQRL_SERVER_TOKEN_NUT "_LIBSQRL_NUT_"

#define SQRL_SERVER_USER_FLAG_DISABLED   0x01

#define SQRL_SERVER_CONTEXT_FLAG_VALID_IDS           0x0001
#define SQRL_SERVER_CONTEXT_FLAG_VALID_PIDS          0x0002
#define SQRL_SERVER_CONTEXT_FLAG_VALID_URS           0x0004
#define SQRL_SERVER_CONTEXT_FLAG_VALID_QUERY         0x0008
#define SQRL_SERVER_CONTEXT_FLAG_VALID_SERVER_STRING 0x0010
#define SQRL_SERVER_CONTEXT_FLAG_VALID_CLIENT_STRING 0x0020

#define CONTEXT_KV_COUNT  5
#define CONTEXT_KV_LENGTH 6
#define CONTEXT_KV_SERVER 0
#define CONTEXT_KV_CLIENT 1
#define CONTEXT_KV_IDS    2
#define CONTEXT_KV_PIDS   3
#define CONTEXT_KV_URS    4

#define CLIENT_KV_COUNT 8
#define CLIENT_KV_LENGTH 4
#define CLIENT_KV_VER  0
#define CLIENT_KV_CMD  1
#define CLIENT_KV_OPT  2
#define CLIENT_KV_BTN  3
#define CLIENT_KV_IDK  4
#define CLIENT_KV_PIDK 5
#define CLIENT_KV_SUK  6
#define CLIENT_KV_VUK  7

#define SERVER_KV_COUNT 9
#define SERVER_KV_LENGTH 3
#define SERVER_KV_VER 0
#define SERVER_KV_NUT 1
#define SERVER_KV_TIF 2
#define SERVER_KV_QRY 3
#define SERVER_KV_SUK 4
#define SERVER_KV_ASK 5
#define SERVER_KV_URL 6
#define SERVER_KV_SFN 7
#define SERVER_KV_MAC 8


typedef struct Sqrl_Server_User {
    uint8_t idk[SQRL_KEY_SIZE];
    uint8_t suk[SQRL_KEY_SIZE];
    uint8_t vuk[SQRL_KEY_SIZE];
    uint16_t flags;
} Sqrl_Server_User;

typedef struct Sqrl_Server {
    Sqrl_Uri *uri;
    char *sfn;
    uint8_t key[32];
    uint64_t nut_expires;
} Sqrl_Server;

#pragma pack(push,4)
typedef struct Sqrl_Nut {
    uint32_t ip;
    uint32_t random;
    uint64_t timestamp;
} Sqrl_Nut;
#pragma pack(pop)

typedef struct Sqrl_Server_Context {
    Sqrl_Server *server;
    Sqrl_Server_User *user;
    Sqrl_Nut nut;
    Sqrl_Cmd command;
    Sqrl_Tif tif;
    uint16_t flags;
    char *context_strings[CONTEXT_KV_COUNT];
    char *client_strings[CLIENT_KV_COUNT];
    char *server_strings[SERVER_KV_COUNT];
} Sqrl_Server_Context;


bool sqrl_server_init( 
    Sqrl_Server *server,
    char *uri,
    char *sfn,
    char *passcode,
    size_t passcode_len,
    int nut_life );
void sqrl_server_clear( Sqrl_Server *server );
Sqrl_Server *sqrl_server_create(
    char *uri,
    char *sfn,
    char *passcode,
    size_t passcode_len,
    int nut_life );
Sqrl_Server *sqrl_server_destroy( Sqrl_Server *server );

bool sqrl_server_nut_generate( 
    Sqrl_Server *server,
    Sqrl_Nut *nut, 
    uint32_t ip );
bool sqrl_server_nut_decrypt(
    Sqrl_Server *server,
    Sqrl_Nut *nut );

Sqrl_Server_Context *sqrl_server_context_create( Sqrl_Server *server );
Sqrl_Server_Context *sqrl_server_context_destroy( Sqrl_Server_Context *context );
void sqrl_server_add_mac( Sqrl_Server *server, UT_string *str, char sep );
bool sqrl_server_verify_mac( Sqrl_Server *server, UT_string *str ); 

char *sqrl_server_create_link( Sqrl_Server *server, uint32_t ip );
void sqrl_server_parse_query( 
    Sqrl_Server_Context *context, 
    const char *query, 
    size_t query_len );


#endif // SQRL_SERVER_H_INCLUDED