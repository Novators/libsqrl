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
typedef int (sqrl_status_fn)(Sqrl_Status status, int percent, void* data);
typedef int (sqrl_ask_fn)(const char *question, size_t question_len);

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

Usage
-----
Create a new entropy pool with \p sqrl_entropy_create:

~~~{.c}
Sqrl_Entropy_Pool pool = sqrl_entropy_create();
~~~

The entropy pool will spawn a new thread and automatically start collecting entropy.  You
can add your own entropy source (such as a webcam feed) with \p sqrl_entropy_add.
Take a peek at how much entropy is currently in the pool with \p sqrl_entropy_estimate.
When you need to retrieve entropy, call \p sqrl_entropy_get or \p sqrl_entropy_get_blocking.
The first may fail if there is not enough entropy available, and the blocking function will
not return until there is.

It's usually ok to leave the pool running for the duration of your program's execution.
It uses very little resources when not in use.  If you do want to stop the entropy pool,
use \p sqrl_entropy_destroy:

~~~{.c}
pool = sqrl_entropy_destroy( pool );
~~~
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
	/** Exports ONLY the type 2 (Rescue) block */
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
/** @} */ // endgroup storage

/** \defgroup user User Identities

These functions facilitate creating and maintaining user identities.  
@{ */

typedef void* Sqrl_User;

uint16_t sqrl_user_check_flags( Sqrl_User u, uint16_t flags );
void sqrl_user_clear_flags( Sqrl_User u, uint16_t flags );
Sqrl_User sqrl_user_create();
Sqrl_User sqrl_user_destroy( Sqrl_User user );
uint8_t sqrl_user_get_enscrypt_seconds( Sqrl_User u );
uint8_t sqrl_user_get_hint_length( Sqrl_User u );
char *sqrl_user_get_rescue_code( Sqrl_User u );
uint16_t sqrl_user_get_timeout_minutes( Sqrl_User u );
void sqrl_user_hintlock( Sqrl_User user, 
				sqrl_status_fn callback, 
				void *callback_data );
void sqrl_user_hintunlock( Sqrl_User user, 
				char *hint, 
				size_t len, 
				sqrl_status_fn callback, 
				void *callback_data );
bool sqrl_user_is_hintlocked( Sqrl_User user );
void sqrl_user_set_enscrypt_seconds( Sqrl_User u, uint8_t seconds );
void sqrl_user_set_flags( Sqrl_User u, uint16_t flags );
void sqrl_user_set_hint_length( Sqrl_User u, uint8_t length );
bool sqrl_user_set_password( Sqrl_User u, char *password, size_t password_len );
bool sqrl_user_set_rescue_code( Sqrl_User u, char *rc );
void sqrl_user_set_timeout_minutes( Sqrl_User u, uint16_t minutes );


/** @} */ // endgroup user



#endif // SQRL_CLIENT_H_INCLUDED