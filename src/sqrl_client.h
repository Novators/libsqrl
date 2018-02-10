/** @file sqrl_client.h 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/  
#ifndef SQRL_CLIENT_H_INCLUDED
#define SQRL_CLIENT_H_INCLUDED

#include "sqrl_common.h"

#define SQRL_UNIQUE_ID_LENGTH 				    43
#define SQRL_LOCAL_KEY_LENGTH 				    32
#define SQRL_RESCUE_CODE_LENGTH 			    24

// User Option Flags
#define SQRL_OPTION_CHECK_FOR_UPDATES		0x0001
#define SQRL_OPTION_ASK_FOR_IDENTITY		0x0002
#define SQRL_OPTION_REQUEST_SQRL_ONLY		0x0004
#define SQRL_OPTION_REQUEST_ID_LOCK			0x0008
#define SQRL_OPTION_WARN_MITM				0x0010
#define SQRL_OPTION_CLEAR_HINT_SUSPEND		0x0020
#define SQRL_OPTION_CLEAR_HINT_USER_SWITCH	0x0040
#define SQRL_OPTION_CLEAR_HINT_IDLE			0x0080

#ifdef DEBUG
// (Much) faster enscrypt during debug...
#define SQRL_DEFAULT_ENSCRYPT_SECONDS 		     1
#define SQRL_RESCUE_ENSCRYPT_SECONDS 			 5
#define SQRL_ENTROPY_NEEDED 					 1
#define SQRL_MILLIS_PER_SECOND 				   100
#define SQRL_HINT_ENSCRYPT_MILLISECONDS 	   100
#else
#define SQRL_DEFAULT_ENSCRYPT_SECONDS 		     5
#define SQRL_RESCUE_ENSCRYPT_SECONDS 		    60
#define SQRL_ENTROPY_NEEDED 				   512
#define SQRL_MILLIS_PER_SECOND				  1000
#define SQRL_HINT_ENSCRYPT_MILLISECONDS 	  1000
#endif



/**
\p Sqrl_Encoding specifies the type of encoding to use when exporting / saving.
*/
typedef enum {
    /** Binary Format */
    SQRL_ENCODING_BINARY = 0,
    /** base64 Encoded Format (larger, but safe for text file)*/
    SQRL_ENCODING_BASE64,
    /** base56check Encoded Format (Used for textual import/export) **/
    SQRL_ENCODING_BASE56
} Sqrl_Encoding;

/**
\p SqrlExport specifies the type of export to perform.
*/
typedef enum {
    /** Exports ALL blocks in the storage object */
    SQRL_EXPORT_ALL = 0,
    /** Exports ONLY the type 2 (Rescue) and type 3 (Previous) blocks */
    SQRL_EXPORT_RESCUE
} Sqrl_Export;


/** \defgroup user User Identities

These functions facilitate creating and maintaining user identities.  
@{ */

typedef void* Sqrl_User;

uint16_t   sqrl_user_check_flags( Sqrl_User u, uint16_t flags );
void       sqrl_user_clear_flags( Sqrl_User u, uint16_t flags );
Sqrl_User  sqrl_user_find( const char *unique_id );
Sqrl_User  sqrl_user_release( Sqrl_User user );
Sqrl_User  sqrl_user_hold( Sqrl_User user );
uint8_t    sqrl_user_get_enscrypt_seconds( Sqrl_User u );
uint16_t   sqrl_user_get_flags( Sqrl_User u );
uint8_t    sqrl_user_get_hint_length( Sqrl_User u );
char*      sqrl_user_get_rescue_code( Sqrl_User u );
uint16_t   sqrl_user_get_timeout_minutes( Sqrl_User u );
void       sqrl_user_set_enscrypt_seconds( Sqrl_User u, uint8_t seconds );
void       sqrl_user_set_flags( Sqrl_User u, uint16_t flags );
void       sqrl_user_set_hint_length( Sqrl_User u, uint8_t length );
bool       sqrl_user_set_rescue_code( Sqrl_User u, char *rc );
void       sqrl_user_set_timeout_minutes( Sqrl_User u, uint16_t minutes );
bool       sqrl_user_unique_id( Sqrl_User u, char *buffer );
bool       sqrl_user_unique_id_match( Sqrl_User u, const char *unique_id );

/** @} */ // endgroup user


/**
\defgroup Client SQRL Client API

@{ */

/**
Indicates which button the user selected in response to an ASK
*/
typedef enum {
	SQRL_BUTTON_CANCEL = 0,
	SQRL_BUTTON_FIRST  = 1,
	SQRL_BUTTON_SECOND = 2,
	SQRL_BUTTON_OK     = 3
} Sqrl_Button;

/**
Type of credential that libsqrl needs to continue a \p Sqrl_Transaction
*/
typedef enum {
	SQRL_CREDENTIAL_PASSWORD,
	SQRL_CREDENTIAL_HINT,
	SQRL_CREDENTIAL_RESCUE_CODE,
	SQRL_CREDENTIAL_NEW_PASSWORD
} Sqrl_Credential_Type;

/**
Type of \p Sqrl_Transaction
*/
typedef enum {
	SQRL_TRANSACTION_UNKNOWN = 0,
	SQRL_TRANSACTION_AUTH_QUERY,
	SQRL_TRANSACTION_AUTH_IDENT,
	SQRL_TRANSACTION_AUTH_DISABLE,
	SQRL_TRANSACTION_AUTH_ENABLE,
	SQRL_TRANSACTION_AUTH_REMOVE,
	SQRL_TRANSACTION_IDENTITY_SAVE,
	SQRL_TRANSACTION_IDENTITY_RESCUE,
	SQRL_TRANSACTION_IDENTITY_REKEY,
	SQRL_TRANSACTION_IDENTITY_UNLOCK,
	SQRL_TRANSACTION_IDENTITY_LOCK,
	SQRL_TRANSACTION_IDENTITY_LOAD,
	SQRL_TRANSACTION_IDENTITY_GENERATE,
	SQRL_TRANSACTION_IDENTITY_CHANGE_PASSWORD
} Sqrl_Transaction_Type;

/**
Status of \p Sqrl_Transaction
*/
typedef enum {
	SQRL_TRANSACTION_STATUS_SUCCESS = 0,
	SQRL_TRANSACTION_STATUS_FAILED,
	SQRL_TRANSACTION_STATUS_CANCELLED,
	SQRL_TRANSACTION_STATUS_WORKING
} Sqrl_Transaction_Status;

/** Reference to a transaction */
typedef void *Sqrl_Transaction;

/** Called when libsqrl needs a user identity to complete a \p Sqrl_Transaction */
typedef Sqrl_User (sqrl_ccb_select_user)(
	Sqrl_Transaction transaction);

/** Called to give the user an option of authenticating with an alternate identity */
typedef void (sqrl_ccb_select_alternate_identity)(
	Sqrl_Transaction transaction);

/** Called when libsqrl needs a user's credentials to continue a \p Sqrl_Transaction */
typedef bool (sqrl_ccb_authentication_required)(
	Sqrl_Transaction transaction,
	Sqrl_Credential_Type credentialType );

/** Called when a server asks a question of the user.
Client implementations should display a dialog to the user, including the text
of \p message, with buttons labeled "OK" and "CANCEL".  If \p firstButton or
\p secondButton are not NULL, also include options with those labels.  When
the user makes a selection, call \p sqrl_client_answer.

@param transaction The \p Sqrl_Transaction
@param message, message_len A string to display to the user
@param firstButton, firstButton_len A string to display in an optional button
@param secondButton, secondButton_len A string to display in an optional button
*/
typedef void (sqrl_ccb_ask)(
	Sqrl_Transaction transaction,
	const char *message, size_t message_len,
	const char *firstButton, size_t firstButton_len,
	const char *secondButton, size_t secondButton_len );

/** Called when libsqrl wants to send data to a server 

\note Client implementations MUST ensure that a secure (HTTPS) connection
is made with the server!

@param transaction The \p Sqrl_Transaction
@param url The URL to connect to
@param url_len Length of \p url
@param payload The data to send (as request body)
@param payload_len Length of \p payload
*/
typedef void (sqrl_ccb_send)(
	Sqrl_Transaction transaction,
	const char *url, size_t url_len,
	const char *payload, size_t payload_len );

/** Called repeatedly during extended encryption / decryption operations
@param transaction The \p Sqrl_Transaction
@param progress Percentage complete; ranges from 0 to 100 inclusive.
@return 1 to continue operation
@return 0 to cancel operation
*/
typedef int (sqrl_ccb_progress)(
	Sqrl_Transaction transaction,
	int progress );

/**
Called when libsqrl thinks that the user will want to save changes to an
identity.  libsqrl does not automatically save changes, but calls this
function to give the user / client implementer the option.  If you choose to
save, call \p sqrl_client_export_user.
*/
typedef void (sqrl_ccb_save_suggested)(
	Sqrl_User user);

/** Called when a \p Sqrl_Transaction has completed. */
typedef void (sqrl_ccb_transaction_complete)(
	Sqrl_Transaction transaction );

/**
Pointers to the various client callback functions
*/
typedef struct Sqrl_Client_Callbacks {
	sqrl_ccb_select_user *onSelectUser;
	sqrl_ccb_select_alternate_identity *onSelectAlternateIdentity;
	sqrl_ccb_authentication_required *onAuthenticationRequired;
	sqrl_ccb_ask *onAsk;
	sqrl_ccb_send *onSend;
	sqrl_ccb_progress *onProgress;
	sqrl_ccb_save_suggested *onSaveSuggested;
	sqrl_ccb_transaction_complete *onTransactionComplete;
} Sqrl_Client_Callbacks;

void sqrl_client_authenticate(
	Sqrl_Transaction transaction,
	Sqrl_Credential_Type credentialType,
	char *credential, size_t credentialLength );
Sqrl_Transaction_Status sqrl_client_begin_transaction(
	Sqrl_Transaction_Type type,
	Sqrl_User user,
	const char *string,
	size_t string_len );
Sqrl_Transaction_Status sqrl_client_export_user(
	Sqrl_User user,
	const char *uri,
	Sqrl_Export exportType,
	Sqrl_Encoding encodingType );
void sqrl_client_get_callbacks( Sqrl_Client_Callbacks *callbacks );
void sqrl_client_receive( 
	Sqrl_Transaction transaction,
	const char *payload, size_t payload_len );
void sqrl_client_set_callbacks( Sqrl_Client_Callbacks *callbacks );




void sqrl_client_answer( 
	Sqrl_Transaction transaction,
	Sqrl_Button answer );
void sqrl_client_transaction_set_alternate_identity(
	Sqrl_Transaction transaction,
	const char *altIdentity );
Sqrl_Transaction_Type sqrl_transaction_type( Sqrl_Transaction t );
Sqrl_User sqrl_transaction_user( Sqrl_Transaction t );
Sqrl_Transaction_Status sqrl_transaction_status( Sqrl_Transaction t );
size_t sqrl_transaction_string( Sqrl_Transaction t, char *buf, size_t *len );
Sqrl_User sqrl_get_user( const char *unique_id );
/** @} */ // endgroup Client

#endif // SQRL_CLIENT_H_INCLUDED
