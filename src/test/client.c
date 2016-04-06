/* client.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "../sqrl_client.h"
#include <unistd.h>

char t1_password[32] = "the password";
char t1_rescue_code[25] = "894268272655451828340130";
char t1_uid[] = "Tne7wOsRjUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLc";
Sqrl_User t1_user = NULL;
char gen_password[32] = "abcdef";
char gen_rescue_code[25];
char gen_uid[SQRL_UNIQUE_ID_LENGTH + 1];
char *gen_data;
char load_uid[SQRL_UNIQUE_ID_LENGTH + 1];
Sqrl_User load_user = NULL;
Sqrl_User gen_user = NULL;

char *password = t1_password;
char *rescueCode = t1_rescue_code;

#define PC(a,b) printf( "%10s: %s\n", (a), (b))

bool onAuthenticationRequired(
    Sqrl_Client_Transaction *transaction,
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
        len = sqrl_user_get_hint_length( transaction->user );
        cred = malloc( len + 1 );
        strncpy( cred, password, len );
        break;
    case SQRL_CREDENTIAL_RESCUE_CODE:
        PC( "AUTH_REQ", "Rescue Code" );
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
int onProgress( Sqrl_Client_Transaction *transaction, int p )
{
    if( !showingProgress ) {
        // Transaction type
        showingProgress = true;
        nextProgress = 2;
        printf( "%10s: ", transactionType[transaction->type] );
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
            sqrl_user_hold( transaction->user );
            if( !t1_user ) {
                t1_user = transaction->user;
            } else if( !load_user ) {
                load_user = transaction->user;
                sqrl_user_unique_id( load_user, load_uid );
            } else {
                PC( "FAIL", "Loaded too many users!" );
                exit(1);
            }
            break;
        case SQRL_TRANSACTION_IDENTITY_GENERATE:
            gen_user = transaction->user;
            sqrl_user_hold( gen_user );
            char *rc = sqrl_user_get_rescue_code( gen_user );
            strcpy( gen_rescue_code, rc );
            PC( "GEN_RC", gen_rescue_code );
            sqrl_client_export_user( gen_user, NULL, SQRL_EXPORT_ALL, SQRL_ENCODING_BASE64 );
            break;
        case SQRL_TRANSACTION_IDENTITY_SAVE:
            if( !gen_data ) {
                gen_data = malloc( transaction->string_len + 1 );
                strcpy( gen_data, transaction->string );
                sqrl_user_unique_id( gen_user, gen_uid );
                PC( "GEN_UID", gen_uid );
                PC( "GEN_DATA", gen_data );
            }
        default:
            break;
        }
    }
}

void onSaveSuggested( Sqrl_User user )
{
    char buf[44];
    sqrl_user_unique_id( user, buf );
    if( strlen( buf ) == 0 ) {
        PC( "SAVE_SUG", "New Identity" );
    } else {
        PC( "SAVE_SUG", buf );
    }
}


int main() 
{
    sqrl_init();
    bool bError = false;
    char txtBuffer[1024] = {0};
    
    Sqrl_Client_Callbacks cbs;
    memset( &cbs, 0, sizeof( Sqrl_Client_Callbacks ));
    cbs.onAuthenticationRequired = onAuthenticationRequired;
    cbs.onProgress = onProgress;
    cbs.onTransactionComplete = onTransactionComplete;
    cbs.onSaveSuggested = onSaveSuggested;
    sqrl_client_set_callbacks( &cbs );

    if( SQRL_TRANSACTION_STATUS_SUCCESS != sqrl_client_begin_transaction( SQRL_TRANSACTION_IDENTITY_LOAD, NULL, "file://test1.sqrl", 17 )) {
        printf( "Failed to Load Identity!\n" );
        exit(1);
    }
    sqrl_user_unique_id( t1_user, txtBuffer );
    PC( "USER", txtBuffer );
    if( 0 != strcmp( txtBuffer, t1_uid )) {
        PC( "EXPCTD", t1_uid );
        exit(1);
    }

    password = gen_password;
    rescueCode = gen_rescue_code;
    if( SQRL_TRANSACTION_STATUS_SUCCESS != sqrl_client_begin_transaction( SQRL_TRANSACTION_IDENTITY_GENERATE, NULL, NULL, 0 )) {
        PC( "FAIL", "Generate Identity" );
        exit(1);
    } else {
        PC( "PASS", "Generate Identity" );
    }

    if( SQRL_TRANSACTION_STATUS_SUCCESS != sqrl_client_begin_transaction( SQRL_TRANSACTION_IDENTITY_LOAD, NULL, gen_data, strlen( gen_data ))) {
        PC( "FAIL", "Load Generated Identity" );
        exit(1);
    }
    if( 0 != strcmp( gen_uid, load_uid )) {
        PC( "FAIL", "gen_uid == load_uid" );
        exit(1);
    }
    PC( "PASS", "Reload Generated Identity" );

    gen_user = sqrl_user_release( gen_user );
    t1_user = sqrl_user_release( t1_user );
    load_user = sqrl_user_release( load_user );
    PC( "ALL", "PASS" );
}
