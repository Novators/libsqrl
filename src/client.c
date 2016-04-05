/** @file client.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/

#include "sqrl_internal.h"

Sqrl_Client_Callbacks *SQRL_CLIENT_CALLBACKS;

void sqrl_client_get_callbacks( Sqrl_Client_Callbacks *callbacks )
{
	if( !callbacks ) return;
	if( !SQRL_CLIENT_CALLBACKS ) {
		SQRL_CLIENT_CALLBACKS = calloc( 1, sizeof( Sqrl_Client_Callbacks ));
	}
	memcpy( callbacks, SQRL_CLIENT_CALLBACKS, sizeof( Sqrl_Client_Callbacks ));
}

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

void sqrl_client_call_select_user( Sqrl_Client_Transaction *transaction )
{
	if( !SQRL_CLIENT_CALLBACKS || !SQRL_CLIENT_CALLBACKS->onSelectUser ) return;
	(SQRL_CLIENT_CALLBACKS->onSelectUser)( transaction );
}

void sqrl_client_call_select_alternate_identity( Sqrl_Client_Transaction *transaction )
{
	if( !SQRL_CLIENT_CALLBACKS || !SQRL_CLIENT_CALLBACKS->onSelectAlternateIdentity ) return;
	(SQRL_CLIENT_CALLBACKS->onSelectAlternateIdentity)( transaction );
}

bool sqrl_client_call_authentication_required( Sqrl_Client_Transaction *transaction, Sqrl_Credential_Type credentialType )
{
	if( !SQRL_CLIENT_CALLBACKS || !SQRL_CLIENT_CALLBACKS->onAuthenticationRequired ) return false;
	return (SQRL_CLIENT_CALLBACKS->onAuthenticationRequired)( transaction, credentialType );
}

void sqrl_client_call_ask(
	Sqrl_Client_Transaction *transaction,
	const char *message, size_t message_len,
	const char *firstButton, size_t firstButton_len,
	const char *secondButton, size_t secondButton_len )
{
	if( !SQRL_CLIENT_CALLBACKS || !SQRL_CLIENT_CALLBACKS->onAsk ) return;
	(SQRL_CLIENT_CALLBACKS->onAsk)( transaction, message, message_len,
		firstButton, firstButton_len, secondButton, secondButton_len );
}

void sqrl_client_call_send(
	Sqrl_Client_Transaction *transaction,
	const char *url, size_t url_len,
	const char *payload, size_t payload_len )
{
	if( !SQRL_CLIENT_CALLBACKS || !SQRL_CLIENT_CALLBACKS->onSend ) return;
	(SQRL_CLIENT_CALLBACKS->onSend)( transaction, url, url_len, payload, payload_len );
}

int sqrl_client_call_progress(
	Sqrl_Client_Transaction *transaction,
	int progress )
{
	if( !SQRL_CLIENT_CALLBACKS || !SQRL_CLIENT_CALLBACKS->onProgress ) {
		return 1;
	}
	return (SQRL_CLIENT_CALLBACKS->onProgress)( transaction, progress );

}

void sqrl_client_call_save_suggested(
	Sqrl_User *user)
{
	if( !SQRL_CLIENT_CALLBACKS || !SQRL_CLIENT_CALLBACKS->onSaveSuggested ) return;
	(SQRL_CLIENT_CALLBACKS->onSaveSuggested)(user);
}

DLL_PUBLIC
void sqrl_client_authenticate(
	Sqrl_Client_Transaction *transaction,
	Sqrl_Credential_Type credentialType,
	char *credential, size_t credentialLength )
{
	if( !transaction ) return;
	WITH_USER(user,transaction->user);
	if( !user ) return;
	switch( credentialType ) {
	case SQRL_CREDENTIAL_PASSWORD:
		sqrl_user_set_password( transaction->user, credential, credentialLength );
		break;
	case SQRL_CREDENTIAL_HINT:
		if( sqrl_user_is_hintlocked( transaction->user )) {
			if( user->options.hintLength == credentialLength ) {
				sqrl_user_hintunlock( transaction->user, credential, credentialLength );
			}
		}
		break;
	case SQRL_CREDENTIAL_RESCUE_CODE:
		if( credentialLength == SQRL_RESCUE_CODE_LENGTH ) {
			sqrl_user_set_rescue_code( transaction->user, credential );
		}
		break;
	}
	END_WITH_USER(user);
	sodium_memzero( credential, credentialLength );
}

bool sqrl_client_require_hint( Sqrl_Client_Transaction *transaction )
{
	if( !transaction ) return false;

	bool retVal = sqrl_user_is_hintlocked( transaction->user );
	if( retVal ) {
		retVal = sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_HINT );
	}
	return retVal;
}

bool sqrl_client_require_password( Sqrl_Client_Transaction *transaction )
{
	if( !transaction ) return false;
	WITH_USER(user,transaction->user);
	if( !user ) return false;
	bool retVal = true;
	if( user->keys->password_len > 0 ) {
		goto DONE;
	}
	if( sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_PASSWORD &&
		user->keys->password_len > 0 )) {
		goto DONE;
	}
	retVal = false;

DONE:
	END_WITH_USER(user);
	return retVal;
}

bool sqrl_client_require_rescue_code( Sqrl_Client_Transaction *transaction )
{
	if( !transaction ) return false;
	if( !transaction->user ) return false;
	bool retVal = true;
	if( sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE ) ) {
		goto DONE;
	}
	if( sqrl_client_call_authentication_required( transaction, SQRL_CREDENTIAL_RESCUE_CODE &&
		sqrl_user_has_key( transaction->user, KEY_RESCUE_CODE) )) {
		goto DONE;
	}
	retVal = false;

DONE:
	return retVal;
}

