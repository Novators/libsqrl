/** @file client.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include "sqrl_internal.h"

Sqrl_Client_Callbacks *SQRL_CLIENT_CALLBACKS;

/**
Makes a copy of the \p Sqrl_Client_Callbacks that libsqrl is currently using.

@param callbacks An allocated \p Sqrl_Client_Callbacks structure
*/
DLL_PUBLIC
void sqrl_client_get_callbacks( Sqrl_Client_Callbacks *callbacks )
{
	if( !callbacks ) return;
	if( !SQRL_CLIENT_CALLBACKS ) {
		SQRL_CLIENT_CALLBACKS = calloc( 1, sizeof( Sqrl_Client_Callbacks ));
	}
	memcpy( callbacks, SQRL_CLIENT_CALLBACKS, sizeof( Sqrl_Client_Callbacks ));
}

/**
Updates the active \p Sqrl_Client_Callbacks.  Libsqrl makes a copy of \p callbacks
to use internally.

@param callbacks The updated callbacks to use
*/
DLL_PUBLIC
void sqrl_client_set_callbacks( Sqrl_Client_Callbacks *callbacks )
{
	if( !callbacks ) {
		if( SQRL_CLIENT_CALLBACKS ) {
			free(SQRL_CLIENT_CALLBACKS);
			SQRL_CLIENT_CALLBACKS = NULL;
		}
		return;
	} else {
		if( !SQRL_CLIENT_CALLBACKS ) {
			SQRL_CLIENT_CALLBACKS = malloc( sizeof( Sqrl_Client_Callbacks ));
		}
		if( SQRL_CLIENT_CALLBACKS ) {
			memcpy( SQRL_CLIENT_CALLBACKS, callbacks, sizeof( Sqrl_Client_Callbacks ));
		}
	}
}

Sqrl_User sqrl_client_call_select_user( Sqrl_Transaction t )
{
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onSelectUser ) {
		Sqrl_User user = (SQRL_CLIENT_CALLBACKS->onSelectUser)( t );
		if( user ) {
			sqrl_transaction_set_user( t, user );
    		return user;
		}
	}
	return NULL;
}

DLL_PUBLIC
void sqrl_client_transaction_set_alternate_identity(
	Sqrl_Transaction t,
	const char *altIdentity )
{
	if( altIdentity ) {
		WITH_TRANSACTION(transaction,t);
		if( !transaction ) return;
		if( transaction->altIdentity ) {
			free( transaction->altIdentity );
		}
		size_t len = strlen( altIdentity );
		if( len > 0 ) {
			transaction->altIdentity = malloc( len + 1 );
			strcpy( transaction->altIdentity, altIdentity );
		}
		END_WITH_TRANSACTION(transaction);
	}
}

void sqrl_client_call_select_alternate_identity( Sqrl_Transaction t )
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return;	
	if( transaction->altIdentity ) {
		free( transaction->altIdentity );
		transaction->altIdentity = NULL;
	}
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onSelectAlternateIdentity ) {
		(SQRL_CLIENT_CALLBACKS->onSelectAlternateIdentity)( t );
	}
	END_WITH_TRANSACTION(transaction);
}

bool sqrl_client_call_authentication_required( Sqrl_Transaction t, Sqrl_Credential_Type credentialType )
{
	bool retVal = false;
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onAuthenticationRequired ) {
		retVal = (SQRL_CLIENT_CALLBACKS->onAuthenticationRequired)( t, credentialType );
	}
	return retVal;
}

void sqrl_client_call_ask(
	Sqrl_Transaction t,
	const char *message, size_t message_len,
	const char *firstButton, size_t firstButton_len,
	const char *secondButton, size_t secondButton_len )
{
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onAsk ) {
		(SQRL_CLIENT_CALLBACKS->onAsk)( t, message, message_len,
			firstButton, firstButton_len, secondButton, secondButton_len );
	}
}

void sqrl_client_call_send(
	Sqrl_Transaction t,
	const char *url, size_t url_len,
	const char *payload, size_t payload_len )
{
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onSend ) {
		(SQRL_CLIENT_CALLBACKS->onSend)( t, url, url_len, payload, payload_len );
	}
}

int sqrl_client_call_progress(
	Sqrl_Transaction t,
	int progress )
{
	int retVal = 1;
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onProgress ) {
		retVal = (SQRL_CLIENT_CALLBACKS->onProgress)( t, progress );
	}
	return retVal;

}

void sqrl_client_call_save_suggested(
	Sqrl_User u)
{
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onSaveSuggested ) {
		(SQRL_CLIENT_CALLBACKS->onSaveSuggested)(u);
	}
}

void sqrl_client_call_transaction_complete(
	Sqrl_Transaction t )
{
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onTransactionComplete ) {
		(SQRL_CLIENT_CALLBACKS->onTransactionComplete)(t);
	}
}

/**
Authenticates the user to libsqrl.  This should only be called in response to 
a \p sqrl_ccb_authentication_required request.

\note \p sqrl_client_authenticate WILL securely zero the \p credential string.

@param transaction The \p Sqrl_Transaction
@param credentialType One of \p Sqrl_Credential_Type
@param credential String containing user's password, rescue code, etc.
@param credentialLength Length of \p credential
*/
DLL_PUBLIC
void sqrl_client_authenticate(
	Sqrl_Transaction t,
	Sqrl_Credential_Type credentialType,
	char *credential, size_t credentialLength )
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return;
	SQRL_CAST_USER(user,transaction->user);
	if( !user ) {
		END_WITH_TRANSACTION(transaction);
		return;
	}
	switch( credentialType ) {
	case SQRL_CREDENTIAL_PASSWORD:
		sqrl_user_set_password( transaction->user, credential, credentialLength );
		break;
	case SQRL_CREDENTIAL_HINT:
		if( sqrl_user_is_hintlocked( transaction->user )) {
			if( user->options.hintLength == credentialLength ) {
				sqrl_user_hintunlock( transaction, credential, credentialLength );
			}
		}
		break;
	case SQRL_CREDENTIAL_RESCUE_CODE:
		if( credentialLength == SQRL_RESCUE_CODE_LENGTH ) {
			sqrl_user_set_rescue_code( transaction->user, credential );
		}
		break;
	case SQRL_CREDENTIAL_NEW_PASSWORD:
		if( transaction->type == SQRL_TRANSACTION_IDENTITY_CHANGE_PASSWORD ) {
			sqrl_user_set_password( transaction->user, credential, credentialLength );
			sqrl_client_call_save_suggested( transaction->user );
		}
		break;
	}
	END_WITH_TRANSACTION(transaction);
	sodium_memzero( credential, credentialLength );
}

bool sqrl_client_require_hint( Sqrl_Transaction t )
{
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return false;

	bool retVal = sqrl_user_is_hintlocked( transaction->user );
	if( retVal ) {
		sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_HINT );
	}
	END_WITH_TRANSACTION(transaction);
	return retVal;
}

bool sqrl_client_require_new_password( Sqrl_Transaction t )
{
	bool retVal = true;
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) return false;
	SQRL_CAST_USER(user,transaction->user);
	if( !user ) goto ERROR;
	if( sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_NEW_PASSWORD ) &&
		user->keys->password_len > 0 ) {
		goto DONE;
	}

ERROR:
	retVal = false;

DONE:
	END_WITH_TRANSACTION(transaction);
	return retVal;
}

bool sqrl_client_require_password( Sqrl_Transaction t )
{
	bool retVal = true;
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) goto ERROR;
	SQRL_CAST_USER(user,transaction->user);
	if( !user ) goto ERROR;
	if( user->keys->password_len > 0 ) {
		goto DONE;
	}
	if( sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_PASSWORD ) &&
		user->keys->password_len > 0 ) {
		goto DONE;
	}

ERROR:
	retVal = false;

DONE:
	END_WITH_TRANSACTION(transaction);
	return retVal;
}

bool sqrl_client_require_rescue_code( Sqrl_Transaction t )
{
	bool retVal = true;
	WITH_TRANSACTION(transaction,t);
	if( !transaction ) goto ERROR;
	if( !transaction->user ) goto ERROR;
	if( sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE ) ) {
		goto DONE;
	}
	if( sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_RESCUE_CODE ) &&
		sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE) ) {
		goto DONE;
	}

ERROR:
	retVal = false;

DONE:
	END_WITH_TRANSACTION( transaction );
	return retVal;
}

/**
Exports a \p Sqrl_User to GRC's S4 format

@param user The \p Sqrl_User
@param uri A \p Sqrl_Uri specifying the file path to save to.  If not specified, export will be returned to the \p sqrl_ccb_transaction_complete callback as a string.
@param exportType \p Sqrl_Export
@param encodingType \p Sqrl_Encoding
@return SQRL_TRANSACION_STATUS_SUCCESS | SQRL_TRANSACTION_STATUS_FAILED
*/
DLL_PUBLIC
Sqrl_Transaction_Status sqrl_client_export_user(
	Sqrl_User user,
	const char *uri,
	Sqrl_Export exportType,
	Sqrl_Encoding encodingType )
{
	Sqrl_Transaction_Status status = SQRL_TRANSACTION_STATUS_WORKING;
	Sqrl_Transaction t = sqrl_transaction_create( SQRL_TRANSACTION_IDENTITY_SAVE );
	SQRL_CAST_TRANSACTION(transaction,t);
	sqrl_transaction_set_user( t, user );
	transaction->status = status;
	transaction->exportType = exportType;
	transaction->encodingType = encodingType;
	if( uri ) {
		transaction->uri = sqrl_uri_parse( uri );
		if( !transaction->uri ) goto ERROR;
		if( transaction->uri->scheme != SQRL_SCHEME_FILE ) goto ERROR;
		if( !sqrl_user_save( t )) goto ERROR;
	} else {
		if( !sqrl_user_save_to_buffer( t )) goto ERROR;
	}
	status = SQRL_TRANSACTION_STATUS_SUCCESS;
	goto DONE;

ERROR:
	status = SQRL_TRANSACTION_STATUS_FAILED;

DONE:
	transaction->status = status;
	sqrl_client_call_transaction_complete( transaction );

	sqrl_transaction_release( transaction );
	return status;
}

/**
Starts a new \p Sqrl_Transaction

@param type \p Sqrl_Transaction_Type of transaction
@param user A \p Sqrl_User, or NULL
@param string A string representing a uri (SQRL or FILE) or an imported (text / base64) S4 identity.
@param string_len Length of \p string
@return \p Sqrl_Transaction_Status
*/
DLL_PUBLIC
Sqrl_Transaction_Status sqrl_client_begin_transaction (
	Sqrl_Transaction_Type type,
	Sqrl_User user,
	const char *string,
	size_t string_len )
{
	sqrl_client_transact( type, user, string, string_len, NULL );
}

/**
Starts a new tagged \p Sqrl_Transaction

@param type \p Sqrl_Transaction_Type of transaction
@param user A \p Sqrl_User, or NULL
@param string A string representing a uri (SQRL or FILE) or an imported (text / base64) S4 identity.
@param string_len Length of \p string
@param tag Pointer to Tag
@return \p Sqrl_Transaction_Status
*/
DLL_PUBLIC
Sqrl_Transaction_Status sqrl_client_transact (
	Sqrl_Transaction_Type type,
	Sqrl_User user,
	const char *string,
	size_t string_len,
	void *tag )
{
	Sqrl_Transaction_Status retVal = SQRL_TRANSACTION_STATUS_WORKING;
	Sqrl_User tmpUser;
	Sqrl_Transaction t = sqrl_transaction_create( type );
	SQRL_CAST_TRANSACTION(transaction,t);
	transaction->tag = tag;
	transaction->status = retVal;

	if( string ) {
		transaction->uri = sqrl_uri_parse( string );
	}
	if( user ) sqrl_transaction_set_user( t, user );
	switch( type ) {
	case SQRL_TRANSACTION_UNKNOWN:
		goto ERROR;
	case SQRL_TRANSACTION_AUTH_ENABLE:
	case SQRL_TRANSACTION_AUTH_REMOVE:
	case SQRL_TRANSACTION_AUTH_IDENT:
	case SQRL_TRANSACTION_AUTH_DISABLE:
		if( !transaction->uri || transaction->uri->scheme != SQRL_SCHEME_SQRL ) {
			goto ERROR;
		}
		if( !transaction->user ) {
			sqrl_client_call_select_user( transaction );
			if( !transaction->user ) goto ERROR;
		}
		if( sqrl_user_is_hintlocked( transaction->user )) {
			sqrl_client_require_hint( transaction );
			if( sqrl_user_is_hintlocked( transaction->user )) {
				goto ERROR;
			}
		}
		if( type == SQRL_TRANSACTION_AUTH_ENABLE || type == SQRL_TRANSACTION_AUTH_REMOVE ) {
			if( !sqrl_user_force_rescue( transaction )) {
				printf( "Failed to force rescue\n" );
				goto ERROR;
			}
		}
		retVal = sqrl_client_resume_transaction( transaction, NULL, 0 );
		goto DONE;
	case SQRL_TRANSACTION_IDENTITY_RESCUE:
		if( !transaction->user ) goto ERROR;
		if( sqrl_user_force_rescue( transaction )) {
			goto SUCCESS;
		}
		goto ERROR;
	case SQRL_TRANSACTION_IDENTITY_REKEY:
		if( !transaction->user ) goto ERROR;
		if( !sqrl_user_force_rescue( transaction )) goto ERROR;
		sqrl_user_rekey( transaction );
		if( sqrl_client_require_password( transaction )) {
			sqrl_client_call_save_suggested( transaction->user );
			goto SUCCESS;
		}
		goto ERROR;
	case SQRL_TRANSACTION_IDENTITY_LOAD:
		if( transaction->user ) goto ERROR;
		if( transaction->uri ) {
			if( transaction->uri->scheme != SQRL_SCHEME_FILE ) goto ERROR;
			transaction->user = sqrl_user_create_from_file( transaction->uri->challenge );
			if( transaction->user ) {
				goto SUCCESS;
			}
		} else {
			transaction->user = sqrl_user_create_from_buffer( string, string_len );
			if( transaction->user ) {
				goto SUCCESS;
			}
		}
		goto ERROR;
	case SQRL_TRANSACTION_IDENTITY_GENERATE:
		if( transaction->user ) goto ERROR;
		tmpUser = sqrl_user_create();
		sqrl_transaction_set_user( t, tmpUser );
		sqrl_user_release( tmpUser );
		if( sqrl_user_rekey( t ) && sqrl_client_require_password( t )) {
			sqrl_client_call_save_suggested( transaction->user );
			goto SUCCESS;
		}
		goto ERROR;
	case SQRL_TRANSACTION_IDENTITY_CHANGE_PASSWORD:
		if( !transaction->user ) goto ERROR;
		if( sqrl_user_force_decrypt( transaction )) {
			if( sqrl_client_require_new_password( transaction )) {
				goto SUCCESS;
			}
		}
		goto ERROR;
	default:
		goto ERROR;
	}
	goto DONE;

SUCCESS:
	retVal = SQRL_TRANSACTION_STATUS_SUCCESS;
	goto DONE;

ERROR:
	retVal = SQRL_TRANSACTION_STATUS_FAILED;
	goto DONE;

DONE:
	transaction->status = retVal;
	sqrl_client_call_transaction_complete( t );

	sqrl_transaction_release( t );
	sqrl_client_site_maintenance( false );

	return retVal;
}

/**
Call \p sqrl_client_receive with the server's response to a \p sqrl_ccb_send callback.

@param transaction The \p Sqrl_Transaction
@param payload The entire body of the server's response.
@param payload_len Length of \p payload 
*/
DLL_PUBLIC
void sqrl_client_receive( 
	Sqrl_Transaction transaction,
	const char *payload, size_t payload_len )
{
	sqrl_client_resume_transaction( transaction, payload, payload_len );
}
