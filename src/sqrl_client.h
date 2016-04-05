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

// Defaults for new Identities
#define SQRL_DEFAULT_N_FACTOR 				     9
#define SQRL_DEFAULT_FLAGS 					  0xF1
#define SQRL_DEFAULT_HINT_LENGTH 			     4
#define SQRL_DEFAULT_TIMEOUT_MINUTES 		    15

#ifdef DEBUG
#define SQRL_DEFAULT_ENSCRYPT_SECONDS 		     1
#define SQRL_RESCUE_ENSCRYPT_SECONDS 			 5
#define SQRL_ENTROPY_NEEDED 					 1
#define SQRL_MILLIS_PER_SECOND 				   100
#else
#define SQRL_DEFAULT_ENSCRYPT_SECONDS 		     5
#define SQRL_RESCUE_ENSCRYPT_SECONDS 		    60
#define SQRL_ENTROPY_NEEDED 				   512
#define SQRL_MILLIS_PER_SECOND				  1000
#endif

// For hints, uncomment one or the other...
#define SQRL_HINT_ENSCRYPT_MILLISECONDS 	  1000
//#define SQRL_HINT_ENSCRYPT_ITERATIONS 		20

#define SQRL_BLOCK_USER 					0x0001
#define SQRL_BLOCK_RESCUE 					0x0002
#define SQRL_BLOCK_PREVIOUS					0x0003

#define KEY_MK 			 1
#define KEY_ILK 		 2
#define KEY_PIUK0 		 3
#define KEY_PIUK1		 4
#define KEY_PIUK2		 5
#define KEY_PIUK3		 6
#define KEY_IUK 		 7
#define KEY_LOCAL 		 8
#define KEY_RESCUE_CODE  9
#define KEY_PASSWORD    10

#define KEY_PASSWORD_MAX_LEN 512

typedef void* Sqrl_Key;

/**
\defgroup entropy Entropy Harvester

Modeled after GRC's assembly implementation, this is a cross-platform entropy harvester.  
We collect entropy from various sources (operating system dependant) at regular intervals, 
and feed them into a SHA-512 hash.  The hash state is constantly being modified until a
caller asks for entropy; then the hash is finalized and the 512 bit (64 byte) result is
returned to the caller.  The hash is then re-opened and filled with more entropy.

When first initialized, and after entropy has been retrieved, we collect about 100 
samples per second.  After we reach the target entropy estimate (512 samples), collection
is throttled to approximately 5 samples per second.  This allows us to quickly build 
entropy, and then reduce CPU and power usage when we have enough.  If you want more entropy,
or want to add your own sources, you can do so with the \p sqrl_entropy_add function.

@{ */

/** The Entropy Pool Object */
void sqrl_entropy_add( uint8_t*, size_t );
int  sqrl_entropy_estimate();
int  sqrl_entropy_get( uint8_t*, int );
int  sqrl_entropy_get_blocking( uint8_t*, int );
int  sqrl_entropy_bytes( uint8_t*, int );
/** @} */ // endgroup entropy

/** \defgroup block Secure Storage Blocks

These are convenience functions for working with S4 blocks.  The read / write functions are
particularly useful if you want your files to work on different platforms, but don't want
to worry about byte order.

@{ */
/** 
The S4 Block

The basic unit of storage in S4.  A \p Sqrl_Storage object can contain many of these.
*/
typedef struct Sqrl_Block {
	/** The length of the block, in bytes */
	uint16_t blockLength;
	/** The type of block */
	uint16_t blockType;
	/** An offset into the block where reading or writing will occur */
	uint16_t cur;
	/** Pointer to the actual data of the block */
	uint8_t *data;
} Sqrl_Block;

void 		sqrl_block_clear( Sqrl_Block *block );
Sqrl_Block*	sqrl_block_create();
Sqrl_Block*	sqrl_block_destroy( Sqrl_Block *block );
void 		sqrl_block_free( Sqrl_Block *block );
bool		sqrl_block_init( Sqrl_Block *block, uint16_t blockType, uint16_t blockLength );
int 		sqrl_block_read( Sqrl_Block *block, uint8_t *data, size_t data_len );
uint16_t 	sqrl_block_read_int16( Sqrl_Block *block );
uint32_t 	sqrl_block_read_int32( Sqrl_Block *block );
uint8_t 	sqrl_block_read_int8( Sqrl_Block *block );
bool 		sqrl_block_resize( Sqrl_Block *block, size_t new_size );
uint16_t 	sqrl_block_seek( Sqrl_Block *block, uint16_t dest );
int 		sqrl_block_write( Sqrl_Block *block, uint8_t *data, size_t data_len );
bool 		sqrl_block_write_int16( Sqrl_Block *block, uint16_t value );
bool 		sqrl_block_write_int32( Sqrl_Block *block, uint32_t value );
bool 		sqrl_block_write_int8( Sqrl_Block *block, uint8_t value );
/** @} */ // endgroup block


/** \defgroup storage Secure Storage System (S4)

A simple and secure implementation of the S4 storage format.  When loaded in memory, all 
storage data is guarded against unauthorized access and against swapping to disk (to the 
extent possible).  Storage can be loaded and saved directly to file or from a memory buffer.
We support both binary and base64 storage.

Storage Structure
-----------------
Each storage object consists of a number of blocks.  Block types are defined at 
[GRC's SQRL page](https://www.grc.com/sqrl/storage.htm).  These functions do not care about
the contents of a block, this is just a generic framework for accessing them.

We allocate memory in 4k pages, and use 128 bytes of each page as an index, so a block is
limited to 3968 bytes in this implementation.  At this time, the largest defined block is 
only 157 bytes, so we do not expect this to be a problem.  Keep it in mind, though, if
you are adding your own custom block types.

Block types are unique within a storage object.  Putting a block into storage will overwrite
any other block with the same type.  This makes the whole system simpler to work with, 
prevents the growth of the storage file, and reduces the chance of getting the wrong block.
@{ */

/** The S4 Storage object */
typedef void* Sqrl_Storage;

/**
\p Sqrl_Encoding specifies the type of encoding to use when exporting / saving.
*/
typedef enum {
	/** Binary Format */
	SQRL_ENCODING_BINARY,
	/** base64 Encoded Format (larger, but safe for text file)*/
	SQRL_ENCODING_BASE64
} Sqrl_Encoding;

/**
\p SqrlExport specifies the type of export to perform.
*/
typedef enum {
	/** Exports ALL blocks in the storage object */
	SQRL_EXPORT_ALL,
	/** Exports ONLY the type 2 (Rescue) and type 3 (Previous) blocks */
	SQRL_EXPORT_RESCUE
} Sqrl_Export;

bool		sqrl_storage_block_exists( Sqrl_Storage storage, uint16_t blockType );
bool		sqrl_storage_block_get( Sqrl_Storage storage, Sqrl_Block *block, uint16_t blockType );
bool		sqrl_storage_block_put( Sqrl_Storage storage, Sqrl_Block *block );
bool		sqrl_storage_block_remove( Sqrl_Storage storage, uint16_t blockType );
Sqrl_Storage
			sqrl_storage_create(void);
Sqrl_Storage
			sqrl_storage_destroy( Sqrl_Storage storage );
bool 		sqrl_storage_load_from_buffer( Sqrl_Storage storage, UT_string *buffer );
bool 		sqrl_storage_load_from_file( Sqrl_Storage storage, const char *filename );
bool 		sqrl_storage_save_to_buffer( 
				Sqrl_Storage storage, 
				UT_string *buf, 
				Sqrl_Export etype, 
				Sqrl_Encoding encoding );
int 		sqrl_storage_save_to_file( 
				Sqrl_Storage storage, 
				const char *filename, 
				Sqrl_Export etype,
				Sqrl_Encoding encoding );
void 		sqrl_storage_unique_id( 
				Sqrl_Storage storage, 
				char *unique_id );
/** @} */ // endgroup storage

/** \defgroup user User Identities

These functions facilitate creating and maintaining user identities.  
@{ */

typedef void* Sqrl_User;

uint16_t   sqrl_user_check_flags( Sqrl_User u, uint16_t flags );
void       sqrl_user_clear_flags( Sqrl_User u, uint16_t flags );
Sqrl_User  sqrl_user_find( const char *unique_id );
Sqrl_User  sqrl_user_release( Sqrl_User user );
bool       sqrl_user_hold( Sqrl_User user );
uint8_t    sqrl_user_get_enscrypt_seconds( Sqrl_User u );
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
\defgroup URL SQRL URL Functions

@{ */

typedef enum {
	SQRL_SCHEME_SQRL,
	SQRL_SCHEME_FILE
} Sqrl_Scheme;

/**
A structure to hold information about a parsed SQRL URL
*/
typedef struct Sqrl_Uri {
	/** The entire SQRL URL */
	char *challenge;
	/** The domain + extension */
	char *host;
	/** Internal use */
	char *prefix;
	/** the https url */
	char *url;
	/** Internal use */
	Sqrl_Scheme scheme;
} Sqrl_Uri;

Sqrl_Uri*	sqrl_uri_create_copy( Sqrl_Uri *original );
Sqrl_Uri*	sqrl_uri_parse(const char *);
Sqrl_Uri*	sqrl_uri_free(struct Sqrl_Uri *);

/** @} */ // endgroup URL

/**
\defgroup Client SQRL Client API

@{ */


typedef enum {
	SQRL_BUTTON_CANCEL = 0,
	SQRL_BUTTON_FIRST  = 1,
	SQRL_BUTTON_SECOND = 2,
	SQRL_BUTTON_OK     = 3
} Sqrl_Button;

typedef enum {
	SQRL_CREDENTIAL_PASSWORD,
	SQRL_CREDENTIAL_HINT,
	SQRL_CREDENTIAL_RESCUE_CODE,
	SQRL_CREDENTIAL_OLD_PASSWORD
} Sqrl_Credential_Type;

typedef enum {
	SQRL_TRANSACTION_UNKNOWN = 0,
	SQRL_TRANSACTION_IDENT,
	SQRL_TRANSACTION_DISABLE,
	SQRL_TRANSACTION_ENABLE,
	SQRL_TRANSACTION_REMOVE,
	SQRL_TRANSACTION_SAVE_IDENTITY,
	SQRL_TRANSACTION_RECOVER_IDENTITY,
	SQRL_TRANSACTION_REKEY_IDENTITY,
	SQRL_TRANSACTION_UNLOCK_IDENTITY,
	SQRL_TRANSACTION_LOCK_IDENTITY,
	SQRL_TRANSACTION_LOAD_IDENTITY,
	SQRL_TRANSACTION_CHANGE_PASSWORD
} Sqrl_Transaction_Type;

typedef struct Sqrl_Client_Transaction {
	Sqrl_Transaction_Type type;
	Sqrl_User *user;
	Sqrl_Uri *url;
	bool altIdentitySpecified;
	char *altIdentity;
	Sqrl_Export exportType;
	Sqrl_Encoding encodingType;
} Sqrl_Client_Transaction;

typedef void (sqrl_ccb_select_user)(
	Sqrl_Client_Transaction *transaction);
typedef void (sqrl_ccb_select_alternate_identity)(
	Sqrl_Client_Transaction *transaction);
typedef bool (sqrl_ccb_authentication_required)(
	Sqrl_Client_Transaction *transaction,
	Sqrl_Credential_Type credentialType );
typedef void (sqrl_ccb_ask)(
	Sqrl_Client_Transaction *transaction,
	const char *message, size_t message_len,
	const char *firstButton, size_t firstButton_len,
	const char *secondButton, size_t secondButton_len );
typedef void (sqrl_ccb_send)(
	Sqrl_Client_Transaction *transaction,
	const char *url, size_t url_len,
	const char *payload, size_t payload_len );
typedef int (sqrl_ccb_progress)(
	Sqrl_Client_Transaction *transaction,
	int progress );
typedef void (sqrl_ccb_save_suggested)(
	Sqrl_User *user);

typedef struct Sqrl_Client_Callbacks {
	sqrl_ccb_select_user *onSelectUser;
	sqrl_ccb_select_alternate_identity *onSelectAlternateIdentity;
	sqrl_ccb_authentication_required *onAuthenticationRequired;
	sqrl_ccb_ask *onAsk;
	sqrl_ccb_send *onSend;
	sqrl_ccb_progress *onProgress;
	sqrl_ccb_save_suggested *onSaveSuggested;
} Sqrl_Client_Callbacks;
void sqrl_client_get_callbacks( Sqrl_Client_Callbacks *callbacks );
void sqrl_client_set_callbacks( Sqrl_Client_Callbacks *callbacks );

Sqrl_Client_Transaction *sqrl_client_begin_transaction(
	Sqrl_Transaction_Type type,
	const char *uri, size_t uri_len );
Sqrl_Client_Transaction *sqrl_client_end_transaction(
	Sqrl_Client_Transaction *transaction );
void sqrl_client_answer( 
	Sqrl_Client_Transaction *transaction,
	Sqrl_Button answer );
void sqrl_client_receive( 
	Sqrl_Client_Transaction *transaction,
	const char *payload, size_t payload_len );
void sqrl_client_authenticate(
	Sqrl_Client_Transaction *transaction,
	Sqrl_Credential_Type credentialType,
	char *credential, size_t credentialLength );
void sqrl_client_transaction_rescue(
	Sqrl_Client_Transaction *transaction,
	const char *rescue_code );
void sqrl_client_transaction_set_user(
	Sqrl_Client_Transaction *transaction,
	Sqrl_User user );
void sqrl_client_transaction_set_alternate_identity(
	Sqrl_Client_Transaction *transaction,
	const char *altIdentity );
Sqrl_User sqrl_get_user( const char *unique_id );
/** @} */ // endgroup Client

#endif // SQRL_CLIENT_H_INCLUDED