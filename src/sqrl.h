#pragma once

#ifndef DLL_PUBLIC
#define DLL_PUBLIC
#endif

#define SQRL_LIB_VERSION_MAJOR 1
#define SQRL_LIB_VERSION_MINOR 1
#define SQRL_LIB_VERSION_BUILD 16201
#define SQRL_LIB_VERSION_REVISION 1
#define SQRL_LIB_VERSION "1.1.16201.1"

#include <stdint.h>
#include "utstring.h"
#include "SqrlBlock.fwd.h"
#include "SqrlStorage.fwd.h"
#include "SqrlTransaction.fwd.h"
#include "SqrlUri.fwd.h"
#include "SqrlUser.fwd.h"

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

DLL_PUBLIC int 		sqrl_init();
DLL_PUBLIC int         sqrl_stop();
size_t		Sqrl_Version(char *buffer, size_t buffer_len);
uint16_t Sqrl_Version_Major();
uint16_t Sqrl_Version_Minor();
uint16_t Sqrl_Version_Build();
uint16_t Sqrl_Version_Revision();

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


#ifdef UNIX
typedef pthread_t SqrlThread;
#define SQRL_THREAD_FUNCTION_RETURN_TYPE void*
#define SQRL_THREAD_FUNCTION_INPUT_TYPE void*
#define SQRL_THREAD_LEAVE pthread_exit(NULL)
#endif

#ifdef WIN32
#include <Windows.h>
typedef HANDLE SqrlThread;
#define SQRL_THREAD_FUNCTION_RETURN_TYPE DWORD
#define SQRL_THREAD_FUNCTION_INPUT_TYPE LPVOID
#define SQRL_THREAD_LEAVE ExitThread(0)
#endif

typedef SQRL_THREAD_FUNCTION_RETURN_TYPE( *sqrl_thread_function )(SQRL_THREAD_FUNCTION_INPUT_TYPE data);

