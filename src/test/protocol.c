/* protocol.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_client.h"
#include "../sqrl_server.h"
#include <unistd.h>

char password[32] = "the password";
char rescue_code[25] = "894268272655451828340130";
char uid[] = "Tne7wOsRjUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLc";
Sqrl_User user = NULL;
bool DEBUG_PROTOCOL = false;

Sqrl_Server *server = NULL;

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
        printf( "Requested unknown credential\n" );
        exit(1);
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
    //PC( "SELECT", uid );
    return user;
}

Sqrl_Transaction current_transaction = NULL;
#define MAX_LOOPS 25
int loops = 0;

void onSend(
    Sqrl_Transaction transaction,
    const char *url, size_t url_len,
    const char *payload, size_t payload_len )
{
    if( ++loops > MAX_LOOPS ) {
        printf( "MAX_LOOPS\n" );
        return;
    }
    if( DEBUG_PROTOCOL ) {
        PC( "CLIENT", url );
        PC( NULL, payload );
        printf( "\n" );
    }
    current_transaction = transaction;
    Sqrl_Server_Context *ctx = sqrl_server_context_create( server );
    sqrl_server_handle_query( ctx, 0, payload, payload_len );
    ctx = sqrl_server_context_destroy( ctx );
}

void onServerSend(
    Sqrl_Server_Context *context,
    char *reply,
    size_t reply_len )
{
    if( DEBUG_PROTOCOL ) {
        printf( "%10s:\n%s\n\n", "SERVER", reply );
    }
    if( loops > MAX_LOOPS ) {
        return;
    }
    sqrl_client_receive( current_transaction, reply, reply_len );
}

int main() 
{
    sqrl_init();
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

    server = sqrl_server_create( 
        "sqrl://sqrlid.com/auth.php?sfn=_LIBSQRL_SFN_&nut=_LIBSQRL_NUT_",
        "SQRLid", 
        "SQRLid passcode", 15, 
        NULL, onServerSend, 60 );

    if( !server ) {
        printf( "Failed to create server!\n" );
        exit(1);
    }

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

    char *sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS != 
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_IDENT, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "IDENT Failed\n" );
        exit(1);
    }
    if( loops != 5 ) {
        PC( "FAIL", "Initial Login" );
        printf( "5 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "Initial Login" );
    free( sqrlUrl );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_IDENT, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "IDENT(2) Failed\n" );
        exit(1);
    }
    if( loops != 7 ) {
        PC( "FAIL", "Repeat Login" );
        printf( "7 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "Repeat Login" );
    free( sqrlUrl );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_DISABLE, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "DISABLE Failed\n" );
        exit(1);
    }
    if( loops != 9 ) {
        PC( "FAIL", "Disable" );
        printf( "9 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "DISABLE" );
    free( sqrlUrl );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_FAILED !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_IDENT, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "Allowed login to disabled identity\n" );
        exit(1);
    }
    if( loops != 10 ) {
        PC( "FAIL", "Login Disabled" );
        printf( "10 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "Login Disabled" );
    free( sqrlUrl );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_ENABLE, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "Failed to enable SQRL\n" );
        exit(1);
    }
    if( loops != 12 ) {
        PC( "FAIL", "Enable" );
        printf( "12 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "Enable" );
    free( sqrlUrl );

    if( SQRL_TRANSACTION_STATUS_SUCCESS != 
        sqrl_client_begin_transaction( SQRL_TRANSACTION_IDENTITY_REKEY, user, NULL, 0 )) {
        printf( "Rekey Failed\n" );
        exit(1);
    }
    PC( "PASS", "Rekey Identity" );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_IDENT, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "IDENT(3) Failed\n" );
        exit(1);
    }
    if( loops != 14 ) {
        PC( "FAIL", "Rekey Server" );
        printf( "14 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "Rekey Server" );
    free( sqrlUrl );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_IDENT, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "IDENT(4) Failed\n" );
        exit(1);
    }
    if( loops != 16 ) {
        PC( "FAIL", "Repeat Login" );
        printf( "16 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "Repeat Login" );
    free( sqrlUrl );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_DISABLE, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "DISABLE Failed\n" );
        exit(1);
    }
    if( loops != 18 ) {
        PC( "FAIL", "Disable" );
        printf( "18 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "DISABLE" );
    free( sqrlUrl );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_REMOVE, user, sqrlUrl, strlen( sqrlUrl ))) {
        printf( "REMOVE Failed\n" );
        exit(1);
    }
    if( loops != 20 ) {
        PC( "FAIL", "REMOVE" );
        printf( "20 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "REMOVE" );
    free( sqrlUrl );

    sqrlUrl = sqrl_server_create_link( server, 0 );
    if( SQRL_TRANSACTION_STATUS_SUCCESS !=
        sqrl_client_begin_transaction( SQRL_TRANSACTION_AUTH_IDENT, user, sqrlUrl, strlen( sqrlUrl ))) {
        PC( "FAIL", "Login after Remove" );
        exit(1);
    }
    if( loops != 25 ) {
        PC( "FAIL", "Login after Remove" );
        printf( "25 != %d loops\n", loops );
        exit(1);
    }
    PC( "PASS", "Login after Remove" );
    free( sqrlUrl );


    printf( "%10s: %d\n", "Loops", loops );

    user = sqrl_user_release( user );
    return sqrl_stop();
}
