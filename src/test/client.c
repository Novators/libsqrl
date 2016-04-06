/* client.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_client.h"
#include <unistd.h>

char myPassword[] = "the password";
char myRescueCode[] = "894268272655451828340130";
Sqrl_User user = NULL;

#define PC(a,b) printf( "%6s: %s\n", (a), (b))

bool onAuthenticationRequired(
    Sqrl_Client_Transaction *transaction,
    Sqrl_Credential_Type credentialType )
{
    char *cred = NULL;
    uint8_t len;

    switch( credentialType ) {
    case SQRL_CREDENTIAL_PASSWORD:
        PC( "REQ", "Password" );
        cred = malloc( strlen( myPassword ) + 1 );
        strcpy( cred, myPassword );
        break;
    case SQRL_CREDENTIAL_HINT:
        PC( "REQ", "Hint" );
        len = sqrl_user_get_hint_length( transaction->user );
        cred = malloc( len + 1 );
        strncpy( cred, myPassword, len );
        break;
    case SQRL_CREDENTIAL_RESCUE_CODE:
        PC( "REQ", "Rescue Code" );
        printf( "Rescue Code Requested, but not needed!\n" );
        exit(1);
    default:
        return false;
    }
    sqrl_client_authenticate( transaction, credentialType, cred, strlen( cred ));
    if( cred ) {
        free( cred );
    }
    return true;
}

char transactionType[13][10] = {
    "UNKNWN",
    "IDENT",
    "DISABL",
    "ENABLE",
    "REMOVE",
    "SAVE",
    "RESCUE",
    "REKEY",
    "UNLOCK",
    "LOCK",
    "LOAD",
    "GNERAT",
    "CHNGPW"
};
char statusText[4][10] = {
    "SUCCESS",
    "FAILED",
    "CANCELLED",
    "WORKING"
};
bool showingProgress = false;
int nextProgress = 0;
int onProgress( Sqrl_Client_Transaction *transaction, int p )
{
    if( !showingProgress ) {
        // Transaction type
        showingProgress = true;
        nextProgress = 2;
        printf( "%6s: ", transactionType[transaction->type] );
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

void onTransactionComplete( Sqrl_Client_Transaction *transaction )
{
    PC( transactionType[transaction->type], statusText[transaction->status] );
    if( transaction->status == SQRL_TRANSACTION_STATUS_SUCCESS ) {
        switch( transaction->type ) {
        case SQRL_TRANSACTION_IDENTITY_LOAD:
            if( user ) user = sqrl_user_release( user );
            user = transaction->user;
            if( user ) sqrl_user_hold( user );
            break;
        default:
            break;
        }
    }
}

int main() 
{
    sqrl_init();
    bool bError = false;
    char txtBuffer[128] = {0};
    
    Sqrl_Client_Callbacks cbs;
    memset( &cbs, 0, sizeof( Sqrl_Client_Callbacks ));
    cbs.onAuthenticationRequired = onAuthenticationRequired;
    cbs.onProgress = onProgress;
    cbs.onTransactionComplete = onTransactionComplete;
    sqrl_client_set_callbacks( &cbs );

    if( SQRL_TRANSACTION_STATUS_SUCCESS != sqrl_client_begin_transaction( SQRL_TRANSACTION_IDENTITY_LOAD, NULL, "file://test1.sqrl" )) {
        printf( "Failed to Load Identity!\n" );
        exit(1);
    }
    sqrl_user_unique_id( user, txtBuffer );
    PC( "USER", txtBuffer );
    if( 0 != strcmp( txtBuffer, "Tne7wOsRjUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLc" )) {
        PC( "EXPCTD", "Tne7wOsRjUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLc" );
        exit(1);
    }
    PC( "ALL", "PASS" );
}
