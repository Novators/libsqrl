#pragma once

#ifndef DLL_PUBLIC
#define DLL_PUBLIC __declspec( dllimport )
#endif

#define SQRL_LIB_VERSION "1.2016.32"
#define SQRL_LIB_VERSION_MAJOR 1
#define SQRL_LIB_VERSION_MINOR 2016
#define SQRL_LIB_VERSION_BUILD 32

#include <stdint.h>
#include "utstring.h"
#include "SqrlBlock.fwd.h"
#include "SqrlStorage.fwd.h"
#include "SqrlTransaction.fwd.h"
#include "SqrlUri.fwd.h"
#include "SqrlUser.fwd.h"

#define KEY_MK           1
#define KEY_ILK          2
#define KEY_PIUK0        3
#define KEY_PIUK1        4
#define KEY_PIUK2        5
#define KEY_PIUK3        6
#define KEY_IUK          7
#define KEY_LOCAL        8
#define KEY_RESCUE_CODE  9
#define KEY_PASSWORD    10

#define KEY_PASSWORD_MAX_LEN 512
#define KEY_SCRATCH_SIZE 2048

#define USER_MAX_KEYS 16

#define USER_FLAG_MEMLOCKED 	0x0001
#define USER_FLAG_T1_CHANGED	0x0002
#define USER_FLAG_T2_CHANGED	0x0004


typedef struct Sqrl_User_Options {
	/** 16 bit Flags, defined at [grc sqrl storage](https://www.grc.com/sqrl/storage.htm) */
	uint16_t flags;
	/** The number of characters to use for password hints (0 to disable) */
	uint8_t hintLength;
	/** The number of seconds to enscrypt */
	uint8_t enscryptSeconds;
	/** Minutes to hold a hint when system is idle */
	uint16_t timeoutMinutes;
} Sqrl_User_Options;

typedef enum {
	SQRL_SCHEME_INVALID = 0,
	SQRL_SCHEME_SQRL,
	SQRL_SCHEME_FILE
} Sqrl_Scheme;

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

typedef enum {
	SQRL_TRANSACTION_STATUS_SUCCESS = 0,
	SQRL_TRANSACTION_STATUS_FAILED,
	SQRL_TRANSACTION_STATUS_CANCELLED,
	SQRL_TRANSACTION_STATUS_WORKING
} Sqrl_Transaction_Status;

typedef enum {
	SQRL_ENCODING_BINARY = 0,
	SQRL_ENCODING_BASE64
} Sqrl_Encoding;

typedef enum {
	SQRL_EXPORT_ALL = 0,
	SQRL_EXPORT_RESCUE
} Sqrl_Export;

// SQRL_BASE64_PAD_CHAR = 0x3D for = padding.
// SQRL_BASE64_PAD_CHAR = 0x00 for no padding.
#define SQRL_BASE64_PAD_CHAR 				  0x00

// Buffer sizes for keys, etc...
#define SQRL_KEY_SIZE 						    32
#define SQRL_SIG_SIZE 						    64

#define SQRL_OPTION_TOKEN_SQRLONLY      "sqrlonly"
#define SQRL_OPTION_TOKEN_HARDLOCK      "hardlock"
#define SQRL_OPTION_TOKEN_CPS                "cps"
#define SQRL_OPTION_TOKEN_SUK                "suk"
#define SQRL_OPTION_TOKEN_SEPARATOR            '~'

typedef void* SqrlMutex;

typedef enum {
	SQRL_CMD_QUERY,
	SQRL_CMD_IDENT,
	SQRL_CMD_DISABLE,
	SQRL_CMD_ENABLE,
	SQRL_CMD_REMOVE
} Sqrl_Cmd;

typedef unsigned int Sqrl_Tif;

#define SQRL_TIF_ID_MATCH 					 0x0001
#define SQRL_TIF_PREVIOUS_ID_MATCH 			 0x0002
#define SQRL_TIF_IP_MATCH 					 0x0004
#define SQRL_TIF_SQRL_DISABLED 				 0x0008
#define SQRL_TIF_FUNCTION_NOT_SUPPORTED 	 0x0010
#define SQRL_TIF_TRANSIENT_ERR 				 0x0020
#define SQRL_TIF_COMMAND_FAILURE 			 0x0040
#define SQRL_TIF_CLIENT_FAILURE 			 0x0080

typedef struct Sqrl_Crypt_Context
{
	uint8_t *plain_text;
	uint8_t *cipher_text;
	uint16_t text_len;
	uint8_t *add;
	uint16_t add_len;
	uint8_t *tag;
	uint8_t *salt;
	uint8_t *iv;
	uint32_t count;
	uint8_t nFactor;
	uint8_t flags;
} Sqrl_Crypt_Context;

DLL_PUBLIC UT_string*	sqrl_b64u_decode(UT_string * dest, const char *src, size_t src_len);
DLL_PUBLIC void 		sqrl_b64u_decode_append(UT_string *dest, const char *src, size_t src_len);
DLL_PUBLIC UT_string*	sqrl_b64u_encode(UT_string *dest, const uint8_t *src, size_t src_len);
DLL_PUBLIC void 		sqrl_b64u_encode_append(UT_string *dest, const uint8_t *src, size_t src_len);
DLL_PUBLIC uint32_t	sqrl_hex2uint(const char *hex);
DLL_PUBLIC UT_string*	sqrl_urldecode(UT_string *dest, const char *src);
DLL_PUBLIC UT_string*	sqrl_urlencode(UT_string *dest, const char *src);

DLL_PUBLIC int 		sqrl_init();
DLL_PUBLIC int         sqrl_stop();
size_t		Sqrl_Version(char *buffer, size_t buffer_len);
int 		Sqrl_Version_Major();
int 		Sqrl_Version_Minor();
int 		Sqrl_Version_Build();

DLL_PUBLIC void sqrl_entropy_add(uint8_t*, size_t);
DLL_PUBLIC int  sqrl_entropy_estimate();
DLL_PUBLIC int  sqrl_entropy_get(uint8_t*, int);
DLL_PUBLIC int  sqrl_entropy_get_blocking(uint8_t*, int);
DLL_PUBLIC int  sqrl_entropy_bytes(uint8_t*, int);

#define SQRL_BLOCK_USER                     0x0001
#define SQRL_BLOCK_RESCUE                   0x0002
#define SQRL_BLOCK_PREVIOUS                 0x0003

// Defaults for new Identities
#define SQRL_DEFAULT_N_FACTOR                    9
#define SQRL_DEFAULT_FLAGS                    0xF1
#define SQRL_DEFAULT_HINT_LENGTH                 4
#define SQRL_DEFAULT_TIMEOUT_MINUTES            15

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



typedef enum {
	SQRL_BUTTON_CANCEL = 0,
	SQRL_BUTTON_FIRST = 1,
	SQRL_BUTTON_SECOND = 2,
	SQRL_BUTTON_OK = 3
} Sqrl_Button;

typedef enum {
	SQRL_CREDENTIAL_PASSWORD,
	SQRL_CREDENTIAL_HINT,
	SQRL_CREDENTIAL_RESCUE_CODE,
	SQRL_CREDENTIAL_NEW_PASSWORD
} Sqrl_Credential_Type;


