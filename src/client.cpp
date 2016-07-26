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


void sqrl_client_action_set_alternate_identity(
	SqrlAction *action,
	const char *altIdentity )
{
	if( altIdentity ) {
		if( !action ) return;
		size_t len = strlen( altIdentity );
		if( len > 0 ) {
			action->setAltIdentity(altIdentity);
		}
		else {
			action->setAltIdentity(NULL);
		}
	}
}

void sqrl_client_call_select_alternate_identity( SqrlAction *action )
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

void sqrl_client_call_action_complete(
	SqrlAction *t )
{
	if( SQRL_CLIENT_CALLBACKS && SQRL_CLIENT_CALLBACKS->onactionComplete ) {
		(SQRL_CLIENT_CALLBACKS->onactionComplete)(t);
	}
}

/**
Authenticates the user to libsqrl.  This should only be called in response to 
a \p sqrl_ccb_authentication_required request.

\note \p sqrl_client_authenticate WILL securely zero the \p credential string.

@param action The \p Sqrl_action
@param credentialType One of \p Sqrl_Credential_Type
@param credential String containing user's password, rescue code, etc.
@param credentialLength Length of \p credential
*/

void sqrl_client_authenticate(
	SqrlAction *action,
	Sqrl_Credential_Type credentialType,
	char *credential, size_t credentialLength )
{
	if( !action ) return;
	SqrlUser *user = action->getUser();
	if( !user ) return;

	switch( credentialType ) {
	case SQRL_CREDENTIAL_PASSWORD:
		user->setPassword( credential, credentialLength );
		break;
	case SQRL_CREDENTIAL_HINT:
		if( user->isHintLocked()) {
			if( user->getHintLength() == credentialLength ) {
				user->hintUnlock( action, credential, credentialLength );
			}
		}
		break;
	case SQRL_CREDENTIAL_RESCUE_CODE:
		if( credentialLength == SQRL_RESCUE_CODE_LENGTH ) {
			user->setRescueCode( credential );
		}
		break;
	case SQRL_CREDENTIAL_NEW_PASSWORD:
		if( action->getType() == SQRL_action_IDENTITY_CHANGE_PASSWORD ) {
			user->setPassword( credential, credentialLength );
			sqrl_client_call_save_suggested( user );
		}
		break;
	}
	sodium_memzero( credential, credentialLength );
}

bool sqrl_client_require_hint( SqrlAction *action )
{
	if( !action ) return false;

	bool retVal = action->getUser()->isHintLocked();
	if( retVal ) {
		retVal = sqrl_client_call_authentication_required( action, SQRL_CREDENTIAL_HINT );
	}
	return retVal;
}

bool sqrl_client_require_new_password( SqrlAction *action )
{
	bool retVal = true;
	if( !action ) return false;
	if( !action->getUser() ) goto ERR;
	if( sqrl_client_call_authentication_required( action, SQRL_CREDENTIAL_NEW_PASSWORD ) &&
		action->getUser()->getPasswordLength() > 0 ) {
		goto DONE;
	}

ERR:
	retVal = false;

DONE:
	return retVal;
}

bool sqrl_client_require_password( SqrlAction *action )
{
	bool retVal = true;
	if( !action ) goto ERR;
	SqrlUser *user = action->getUser();
	if( !user ) goto ERR;
	if( user->getPasswordLength() > 0 ) {
		goto DONE;
	}
	if( sqrl_client_call_authentication_required( action, SQRL_CREDENTIAL_PASSWORD ) &&
		user->getPasswordLength() > 0 ) {
		goto DONE;
	}

ERR:
	retVal = false;

DONE:
	return retVal;
}

bool sqrl_client_require_rescue_code( SqrlAction *action )
{
	bool retVal = true;
	if( !action ) goto ERR;
	SqrlUser *user = action->getUser();
	if( !user ) goto ERR;
	if( user->hasKey( KEY_RESCUE_CODE ) ) {
		goto DONE;
	}
	if( sqrl_client_call_authentication_required( action, SQRL_CREDENTIAL_RESCUE_CODE ) &&
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
@param uri A \p SqrlUri specifying the file path to save to.  If not specified, export will be returned to the \p sqrl_ccb_action_complete callback as a string.
@param exportType \p Sqrl_Export
@param encodingType \p Sqrl_Encoding
@return SQRL_TRANSACION_STATUS_SUCCESS | SQRL_action_STATUS_FAILED
*/

Sqrl_action_Status sqrl_client_export_user(
	SqrlUser *user,
	const char *uri,
	Sqrl_Export exportType,
	Sqrl_Encoding encodingType )
{
	Sqrl_action_Status status = SQRL_action_STATUS_WORKING;
	SqrlAction *action = new SqrlAction(SQRL_action_IDENTITY_SAVE);
	action->setUser(user);
	action->setStatus(status);
	action->setExportType( exportType );
	action->setEncodingType( encodingType );
	if( uri ) {
		action->setUri(new SqrlUri(uri));
		SqrlUri *suri = action->getUri();
		if( !suri ) goto ERR;
		if( suri->getScheme() != SQRL_SCHEME_FILE ) goto ERR;
		if( ! action->getUser()->save(action)) goto ERR;
	} else {
		if( !action->getUser()->saveToBuffer( action )) goto ERR;
	}
	status = SQRL_action_STATUS_SUCCESS;
	goto DONE;

ERR:
	status = SQRL_action_STATUS_FAILED;

DONE:
	action->setStatus(status);
	sqrl_client_call_action_complete( action );

	action->release();
	return status;
}

/**
Starts a new \p Sqrl_action

@param type \p Sqrl_action_Type of action
@param user A \p Sqrl_User, or NULL
@param string A string representing a uri (SQRL or FILE) or an imported (text / base64) S4 identity.
@param string_len Length of \p string
@return \p Sqrl_action_Status
*/

Sqrl_action_Status sqrl_client_begin_action(
	Sqrl_action_Type type,
	SqrlUser *user,
	const char *string,
	size_t string_len )
{
	Sqrl_action_Status retVal = SQRL_action_STATUS_WORKING;
	SqrlUser *tmpUser;
	SqrlUri *uri;
	SqrlAction *action = new SqrlAction( type );
	action->setStatus(retVal);

	if( string ) {
		uri = new SqrlUri(string);
		action->setUri(uri);
		delete(uri);
	}
	uri = action->getUri();
	if (user) action->setUser(user);
	switch( type ) {
	case SQRL_action_UNKNOWN:
		goto ERR;
	case SQRL_action_AUTH_ENABLE:
	case SQRL_action_AUTH_REMOVE:
	case SQRL_action_AUTH_IDENT:
	case SQRL_action_AUTH_DISABLE:
		if( !uri || uri->getScheme() != SQRL_SCHEME_SQRL ) {
			goto ERR;
		}
		if( !action->getUser() ) {
			sqrl_client_call_select_user( action );
			if( !action->getUser() ) goto ERR;
		}
		if( type == SQRL_action_AUTH_ENABLE || type == SQRL_action_AUTH_REMOVE ) {
			if( !action->getUser()->forceRescue( action )) {
				printf( "Failed to force rescue\n" );
				goto ERR;
			}
		}
		retVal = sqrl_client_resume_action( action, NULL, 0 );
		goto DONE;
	case SQRL_action_IDENTITY_RESCUE:
		if( !action->getUser() ) goto ERR;
		if( action->getUser()->forceRescue( action )) {
			goto SUCCESS;
		}
		goto ERR;
	case SQRL_action_IDENTITY_REKEY:
		if( !action->getUser() ) goto ERR;
		if( !action->getUser()->forceRescue( action )) goto ERR;
		action->getUser()->rekey( action );
		if( sqrl_client_require_password( action )) {
			sqrl_client_call_save_suggested( action->getUser() );
			goto SUCCESS;
		}
		goto ERR;
	case SQRL_action_IDENTITY_LOAD:
		if( action->getUser() ) goto ERR;
		if( uri ) {
			if( uri->getScheme() != SQRL_SCHEME_FILE ) goto ERR;
			tmpUser = new SqrlUser(uri);
			action->setUser(tmpUser);
			tmpUser->release();
			goto SUCCESS;
		} else {
			tmpUser = new SqrlUser(string, string_len);
			action->setUser(tmpUser);
			tmpUser->release();
			goto SUCCESS;
		}
		goto ERR;
	case SQRL_action_IDENTITY_GENERATE:
		if( action->getUser() ) goto ERR;
		tmpUser = new SqrlUser();
		action->setUser(tmpUser);
		tmpUser->release();
		if( action->getUser()->rekey( action ) && sqrl_client_require_password( action )) {
			sqrl_client_call_save_suggested( action->getUser() );
			goto SUCCESS;
		}
		goto ERR;
	case SQRL_action_IDENTITY_CHANGE_PASSWORD:
		if( !action->getUser() ) goto ERR;
		if( action->getUser()->forceDecrypt( action )) {
			if( sqrl_client_require_new_password( action )) {
				goto SUCCESS;
			}
		}
		goto ERR;
	default:
		goto ERR;
	}
	goto DONE;

SUCCESS:
	retVal = SQRL_action_STATUS_SUCCESS;
	goto DONE;

ERR:
	retVal = SQRL_action_STATUS_FAILED;
	goto DONE;

DONE:
	action->setStatus(retVal);
	sqrl_client_call_action_complete( action );
	action->release();
	return retVal;
}

/**
Call \p sqrl_client_receive with the server's response to a \p sqrl_ccb_send callback.

@param action The \p Sqrl_action
@param payload The entire body of the server's response.
@param payload_len Length of \p payload 
*/

void sqrl_client_receive( 
	SqrlAction *action,
	const char *payload, size_t payload_len )
{
	sqrl_client_resume_action( action, payload, payload_len );
}
