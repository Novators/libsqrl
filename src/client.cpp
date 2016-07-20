/** @file client.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include "sqrl_internal.h"
#include "sqrl.h"
#include "SqrlUser.h"
#include "SqrlUri.h"
#include "SqrlAction.h"

Sqrl_Client_Callbacks *SQRL_CLIENT_CALLBACKS;


void sqrl_client_transaction_set_alternate_identity(
	SqrlAction *transaction,
	const char *altIdentity )
{
	if( altIdentity ) {
		if( !transaction ) return;
		size_t len = strlen( altIdentity );
		if( len > 0 ) {
			transaction->setAltIdentity(altIdentity);
		}
		else {
			transaction->setAltIdentity(NULL);
		}
	}
}

void sqrl_client_call_select_alternate_identity( SqrlAction *transaction )
{
}

bool sqrl_client_call_authentication_required( SqrlAction *t, Sqrl_Credential_Type credentialType )
{
	bool retVal = false;
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onAuthenticationRequired ) {
		retVal = (SQRL_CLIENT_CALLBACKS->onAuthenticationRequired)( t, credentialType );
	}
	return retVal;
}

void sqrl_client_call_ask(
	SqrlAction *t,
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
	SqrlAction *t,
	const char *url, size_t url_len,
	const char *payload, size_t payload_len )
{
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onSend ) {
		(SQRL_CLIENT_CALLBACKS->onSend)( t, url, url_len, payload, payload_len );
	}
}

int sqrl_client_call_progress(
	SqrlAction *t,
	int progress )
{
	int retVal = 1;
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onProgress ) {
		retVal = (SQRL_CLIENT_CALLBACKS->onProgress)( t, progress );
	}
	return retVal;

}

void sqrl_client_call_save_suggested(
	SqrlUser *u)
{
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onSaveSuggested ) {
		(SQRL_CLIENT_CALLBACKS->onSaveSuggested)(u);
	}
}

void sqrl_client_call_transaction_complete(
	SqrlAction *t )
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

void sqrl_client_authenticate(
	SqrlAction *transaction,
	Sqrl_Credential_Type credentialType,
	char *credential, size_t credentialLength )
{
	if( !transaction ) return;
	SqrlUser *user = transaction->getUser();
	if( !user ) return;

	switch( credentialType ) {
	case SQRL_CREDENTIAL_PASSWORD:
		user->setPassword( credential, credentialLength );
		break;
	case SQRL_CREDENTIAL_HINT:
		if( user->isHintLocked()) {
			if( user->getHintLength() == credentialLength ) {
				user->hintUnlock( transaction, credential, credentialLength );
			}
		}
		break;
	case SQRL_CREDENTIAL_RESCUE_CODE:
		if( credentialLength == SQRL_RESCUE_CODE_LENGTH ) {
			user->setRescueCode( credential );
		}
		break;
	case SQRL_CREDENTIAL_NEW_PASSWORD:
		if( transaction->getType() == SQRL_TRANSACTION_IDENTITY_CHANGE_PASSWORD ) {
			user->setPassword( credential, credentialLength );
			sqrl_client_call_save_suggested( user );
		}
		break;
	}
	sodium_memzero( credential, credentialLength );
}

bool sqrl_client_require_hint( SqrlAction *transaction )
{
	if( !transaction ) return false;

	bool retVal = transaction->getUser()->isHintLocked();
	if( retVal ) {
		retVal = sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_HINT );
	}
	return retVal;
}

bool sqrl_client_require_new_password( SqrlAction *transaction )
{
	bool retVal = true;
	if( !transaction ) return false;
	if( !transaction->getUser() ) goto ERR;
	if( sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_NEW_PASSWORD ) &&
		transaction->getUser()->getPasswordLength() > 0 ) {
		goto DONE;
	}

ERR:
	retVal = false;

DONE:
	return retVal;
}

bool sqrl_client_require_password( SqrlAction *transaction )
{
	bool retVal = true;
	if( !transaction ) goto ERR;
	SqrlUser *user = transaction->getUser();
	if( !user ) goto ERR;
	if( user->getPasswordLength() > 0 ) {
		goto DONE;
	}
	if( sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_PASSWORD ) &&
		user->getPasswordLength() > 0 ) {
		goto DONE;
	}

ERR:
	retVal = false;

DONE:
	return retVal;
}

bool sqrl_client_require_rescue_code( SqrlAction *transaction )
{
	bool retVal = true;
	if( !transaction ) goto ERR;
	SqrlUser *user = transaction->getUser();
	if( !user ) goto ERR;
	if( user->hasKey( KEY_RESCUE_CODE ) ) {
		goto DONE;
	}
	if( sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_RESCUE_CODE ) &&
		user->hasKey( KEY_RESCUE_CODE) ) {
		goto DONE;
	}

ERR:
	retVal = false;

DONE:
	return retVal;
}

/**
Exports a \p Sqrl_User to GRC's S4 format

@param user The \p Sqrl_User
@param uri A \p SqrlUri specifying the file path to save to.  If not specified, export will be returned to the \p sqrl_ccb_transaction_complete callback as a string.
@param exportType \p Sqrl_Export
@param encodingType \p Sqrl_Encoding
@return SQRL_TRANSACION_STATUS_SUCCESS | SQRL_TRANSACTION_STATUS_FAILED
*/

Sqrl_Transaction_Status sqrl_client_export_user(
	SqrlUser *user,
	const char *uri,
	Sqrl_Export exportType,
	Sqrl_Encoding encodingType )
{
	Sqrl_Transaction_Status status = SQRL_TRANSACTION_STATUS_WORKING;
	SqrlAction *transaction = new SqrlAction(SQRL_TRANSACTION_IDENTITY_SAVE);
	transaction->setUser(user);
	transaction->setStatus(status);
	transaction->setExportType( exportType );
	transaction->setEncodingType( encodingType );
	if( uri ) {
		transaction->setUri(new SqrlUri(uri));
		SqrlUri *suri = transaction->getUri();
		if( !suri ) goto ERR;
		if( suri->getScheme() != SQRL_SCHEME_FILE ) goto ERR;
		if( ! transaction->getUser()->save(transaction)) goto ERR;
	} else {
		if( !transaction->getUser()->saveToBuffer( transaction )) goto ERR;
	}
	status = SQRL_TRANSACTION_STATUS_SUCCESS;
	goto DONE;

ERR:
	status = SQRL_TRANSACTION_STATUS_FAILED;

DONE:
	transaction->setStatus(status);
	sqrl_client_call_transaction_complete( transaction );

	transaction->release();
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

Sqrl_Transaction_Status sqrl_client_begin_transaction(
	Sqrl_Transaction_Type type,
	SqrlUser *user,
	const char *string,
	size_t string_len )
{
	Sqrl_Transaction_Status retVal = SQRL_TRANSACTION_STATUS_WORKING;
	SqrlUser *tmpUser;
	SqrlUri *uri;
	SqrlAction *transaction = new SqrlAction( type );
	transaction->setStatus(retVal);

	if( string ) {
		uri = new SqrlUri(string);
		transaction->setUri(uri);
		delete(uri);
	}
	uri = transaction->getUri();
	if (user) transaction->setUser(user);
	switch( type ) {
	case SQRL_TRANSACTION_UNKNOWN:
		goto ERR;
	case SQRL_TRANSACTION_AUTH_ENABLE:
	case SQRL_TRANSACTION_AUTH_REMOVE:
	case SQRL_TRANSACTION_AUTH_IDENT:
	case SQRL_TRANSACTION_AUTH_DISABLE:
		if( !uri || uri->getScheme() != SQRL_SCHEME_SQRL ) {
			goto ERR;
		}
		if( !transaction->getUser() ) {
			sqrl_client_call_select_user( transaction );
			if( !transaction->getUser() ) goto ERR;
		}
		if( type == SQRL_TRANSACTION_AUTH_ENABLE || type == SQRL_TRANSACTION_AUTH_REMOVE ) {
			if( !transaction->getUser()->forceRescue( transaction )) {
				printf( "Failed to force rescue\n" );
				goto ERR;
			}
		}
		retVal = sqrl_client_resume_transaction( transaction, NULL, 0 );
		goto DONE;
	case SQRL_TRANSACTION_IDENTITY_RESCUE:
		if( !transaction->getUser() ) goto ERR;
		if( transaction->getUser()->forceRescue( transaction )) {
			goto SUCCESS;
		}
		goto ERR;
	case SQRL_TRANSACTION_IDENTITY_REKEY:
		if( !transaction->getUser() ) goto ERR;
		if( !transaction->getUser()->forceRescue( transaction )) goto ERR;
		transaction->getUser()->rekey( transaction );
		if( sqrl_client_require_password( transaction )) {
			sqrl_client_call_save_suggested( transaction->getUser() );
			goto SUCCESS;
		}
		goto ERR;
	case SQRL_TRANSACTION_IDENTITY_LOAD:
		if( transaction->getUser() ) goto ERR;
		if( uri ) {
			if( uri->getScheme() != SQRL_SCHEME_FILE ) goto ERR;
			tmpUser = new SqrlUser(uri);
			transaction->setUser(tmpUser);
			tmpUser->release();
			goto SUCCESS;
		} else {
			tmpUser = new SqrlUser(string, string_len);
			transaction->setUser(tmpUser);
			tmpUser->release();
			goto SUCCESS;
		}
		goto ERR;
	case SQRL_TRANSACTION_IDENTITY_GENERATE:
		if( transaction->getUser() ) goto ERR;
		tmpUser = new SqrlUser();
		transaction->setUser(tmpUser);
		tmpUser->release();
		if( transaction->getUser()->rekey( transaction ) && sqrl_client_require_password( transaction )) {
			sqrl_client_call_save_suggested( transaction->getUser() );
			goto SUCCESS;
		}
		goto ERR;
	case SQRL_TRANSACTION_IDENTITY_CHANGE_PASSWORD:
		if( !transaction->getUser() ) goto ERR;
		if( transaction->getUser()->forceDecrypt( transaction )) {
			if( sqrl_client_require_new_password( transaction )) {
				goto SUCCESS;
			}
		}
		goto ERR;
	default:
		goto ERR;
	}
	goto DONE;

SUCCESS:
	retVal = SQRL_TRANSACTION_STATUS_SUCCESS;
	goto DONE;

ERR:
	retVal = SQRL_TRANSACTION_STATUS_FAILED;
	goto DONE;

DONE:
	transaction->setStatus(retVal);
	sqrl_client_call_transaction_complete( transaction );
	transaction->release();
	return retVal;
}

/**
Call \p sqrl_client_receive with the server's response to a \p sqrl_ccb_send callback.

@param transaction The \p Sqrl_Transaction
@param payload The entire body of the server's response.
@param payload_len Length of \p payload 
*/

void sqrl_client_receive( 
	SqrlAction *transaction,
	const char *payload, size_t payload_len )
{
	sqrl_client_resume_transaction( transaction, payload, payload_len );
}
