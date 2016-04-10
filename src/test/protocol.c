/* protocol.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_client.h"
#include <unistd.h>

char password[32] = "the password";
char rescue_code[25] = "894268272655451828340130";
char uid[] = "Tne7wOsRjUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLc";
Sqrl_User user = NULL;

#define PC(a,b) printf( "%10s: %s\n", (a) ? (a) : "", (b))

bool onAuthenticationRequired(
    Sqrl_Transaction transaction,
    Sqrl_Credential_Type credentialType )
{
    char *cred = NULL;
    uint8_t len;

    switch( credentialType ) {
    case SQRL_CREDENTIAL_PASSWORD:
        PC( "AUTH_REQ", "Password" );
        cred = malloc( strlen( password ) + 1 );
        strcpy( cred, password );
        break;
    case SQRL_CREDENTIAL_HINT:
        PC( "AUTH_REQ", "Hint" );
        len = sqrl_user_get_hint_length( sqrl_transaction_user( transaction ));
        cred = malloc( len + 1 );
        strncpy( cred, password, len );
        break;
    case SQRL_CREDENTIAL_RESCUE_CODE:
        PC( "AUTH_REQ", "Rescue Code" );
        cred = malloc( strlen( rescue_code ) + 1 );
        strcpy( cred, rescue_code );
        break;
    default:
        return false;
    }
    sqrl_client_authenticate( transaction, credentialType, cred, strlen( cred ));
    if( cred ) {
        free( cred );
    }
    return true;
}

char transactionType[14][10] = {
    "UNKNWN",
    "QUERY",
    "IDENT",
    "DISABLE",
    "ENABLE",
    "REMOVE",
    "SAVE",
    "RESCUE",
    "REKEY",
    "UNLOCK",
    "LOCK",
    "LOAD",
    "GENRATE",
    "CHNG_PSWD"
};

char statusText[4][10] = {
    "SUCCESS",
    "FAILED",
    "CANCELLED",
    "WORKING"
};
bool showingProgress = false;
int nextProgress = 0;
int onProgress( Sqrl_Transaction transaction, int p )
{
    if( !showingProgress ) {
        // Transaction type
        showingProgress = true;
        nextProgress = 2;
        printf( "%10s: ", transactionType[sqrl_transaction_type(transaction)] );
    }
    const char sym[] = "|****";
    while( p >= nextProgress ) {
        if( nextProgress != 100 ) {
            printf( "%c", sym[nextProgress%5] );
        }
        nextProgress += 2;
    }
    if( p >= 100 ) {
        printf( "\n" );
        showingProgress = false;
    }
    fflush( stdout );
    return 1;

}

void onTransactionComplete( Sqrl_Transaction transaction )
{
    Sqrl_Transaction_Type type = sqrl_transaction_type( transaction );
    Sqrl_Transaction_Status status = sqrl_transaction_status( transaction );
    PC( transactionType[type], statusText[status] );
    if( status == SQRL_TRANSACTION_STATUS_SUCCESS ) {
        switch( type ) {
        case SQRL_TRANSACTION_IDENTITY_LOAD:
            if( !user ) {
                user = sqrl_user_hold( sqrl_transaction_user( transaction ));
            } else {
                PC( "FAIL", "Loaded too many users!" );
                exit(1);
            }
            break;
        default:
            break;
        }
    }
}

Sqrl_User onSelectUser( Sqrl_Transaction transaction )
{
    PC( "SELECT", uid );
    return user;
}

#define MAX_LOOPS 5
int loop;
char data[MAX_LOOPS][128] = {
"ver=1\r\nnut=nutty0\r\ntif=0\r\nqry=/auth.php\r\n",
"ver=1\r\nnut=nutty1\r\ntif=0\r\nqry=/auth.php\r\n",
"ver=1\r\nnut=nutty2\r\ntif=0\r\nqry=/auth.php\r\n",
"ver=1\r\nnut=nutty3\r\ntif=0\r\nqry=/auth.php\r\n",
"ver=1\r\nnut=nutty4\r\ntif=1\r\nqry=/auth.php\r\n"
};

void onSend(
    Sqrl_Transaction transaction,
    const char *url, size_t url_len,
    const char *payload, size_t payload_len )
{
    PC( "CLIENT", url );
    PC( NULL, payload );
    if( loop++ < MAX_LOOPS ) {
        sqrl_client_receive( transaction, data[loop-1], strlen( data[loop-1] ));
    }
}


int main() 
{
    sqrl_init();
    loop = 0;
    bool bError = false;
    char txtBuffer[4096] = {0};
    
    Sqrl_Client_Callbacks cbs;
    memset( &cbs, 0, sizeof( Sqrl_Client_Callbacks ));
    cbs.onAuthenticationRequired = onAuthenticationRequired;
    cbs.onProgress = onProgress;
    cbs.onTransactionComplete = onTransactionComplete;
    cbs.onSelectUser = onSelectUser;
    cbs.onSend = onSend;
    sqrl_client_set_callbacks( &cbs );

    if( SQRL_TRANSACTION_STATUS_SUCCESS != sqrl_client_begin_transaction( SQRL_TRANSACTION_IDENTITY_LOAD, NULL, "file://test1.sqrl", 17 )) {
        printf( "Failed to Load Identity!\n" );
        exit(1);
    }
    sqrl_user_unique_id( user, txtBuffer );
    PC( "USER", txtBuffer );
    if( 0 != strcmp( txtBuffer, uid )) {
        PC( "EXPECTED", uid );
        exit(1);
    }
    char *sqrlUrl = "sqrl://auth.sqrlid.com/auth.php?nut=blah&sfn=U1FSTGlk";
    if( SQRL_TRANSACTION_STATUS_SUCCESS != 
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_IDENT, NULL, sqrlUrl, strlen( sqrlUrl ))) {
        PC( "INCOMPLETE", "AUTH_IDENT" );
    }
    user = sqrl_user_release( user );
    return sqrl_stop();
}
