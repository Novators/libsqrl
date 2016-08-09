/** \file SqrlServer.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLSERVER_H
#define SQRLSERVER_H

#include "sqrl.h"
#include "SqrlString.h"

namespace libsqrl
{
#define SQRL_DEFAULT_NUT_LIFE 60

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

#define SERVER_KV_COUNT 7
#define SERVER_KV_LENGTH 3
#define SERVER_KV_VER 0
#define SERVER_KV_NUT 1
#define SERVER_KV_TIF 2
#define SERVER_KV_QRY 3
#define SERVER_KV_SUK 4
#define SERVER_KV_ASK 5
#define SERVER_KV_URL 6

#pragma pack(push,4)
    typedef struct Sqrl_Nut
    {
        uint32_t ip;
        uint32_t random;
        uint64_t timestamp;
    } Sqrl_Nut;
#pragma pack(pop)

    class DLL_PUBLIC SqrlServer
    {
    public:
        SqrlServer( const char *uri, const char *sfn, const char *passcode, size_t passcode_len );
        ~SqrlServer();

        SqrlString *createLink( uint32_t ip );
        void handleQuery(
            uint32_t client_ip,
            const char *query,
            size_t query_len );

    protected:
        virtual bool onUserFind( const SqrlString *host, const SqrlString *idk, const SqrlString *pidk ) = 0;
        virtual bool onUserCreate( const SqrlString *host, const SqrlString *idk, const SqrlString *pidk ) = 0;
        virtual bool onUserUpdate( const SqrlString *host, const SqrlString *idk, const SqrlString *pidk ) = 0;
        virtual bool onUserDelete( const SqrlString *host, const SqrlString *idk, const SqrlString *pidk ) = 0;
        virtual bool onUserRekeyed( const SqrlString *host, const SqrlString *idk, const SqrlString *pidk ) = 0;
        virtual bool onUserIdentified( const SqrlString *host, const SqrlString *idk, const SqrlString *pidk ) = 0;
        virtual void onSend( const SqrlString *reply ) = 0;

        SqrlUri *uri;
        SqrlString *sfn;
        uint8_t key[32];
        uint64_t nut_expires;

        Sqrl_Nut nut;
        int command;
        Sqrl_Tif tif;
        uint16_t flags;
        char *context_strings[CONTEXT_KV_COUNT];
        char *client_strings[CLIENT_KV_COUNT];
        char *server_strings[SERVER_KV_COUNT];
        char *reply;

        uint8_t idk[SQRL_KEY_SIZE];
        uint8_t suk[SQRL_KEY_SIZE];
        uint8_t vuk[SQRL_KEY_SIZE];
        uint16_t userFlags;

        void addMAC( SqrlString *str, char sep );
        bool verifyMAC( SqrlString *str );
        bool createNut( Sqrl_Nut *nut, uint32_t ip );
        bool decryptNut( Sqrl_Nut *nut );

    };
}
#endif // SQRLSERVER_H
