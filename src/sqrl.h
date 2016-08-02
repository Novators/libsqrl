#pragma once

#ifndef DLL_PUBLIC
#define DLL_PUBLIC
#endif

#include <stdint.h>
#include <thread>
#include <mutex>
#include <string>

class SqrlUser;
class SqrlEncoder;
class SqrlUrlEncode;
class SqrlUri;
class SqrlStorage;
class SqrlSiteAction;
class SqrlServer;
class SqrlIdentityAction;
class SqrlEntropy;
class SqrlCrypt;
class SqrlClient;
class SqrlClient;
class SqrlBlock;
class SqrlBase64;
class SqrlActionSave;
class SqrlActionRescue;
class SqrlActionRemove;
class SqrlActionRekey;
class SqrlActionLock;
class SqrlActionIdent;
class SqrlActionGenerate;
class SqrlActionEnable;
class SqrlActionDisable;
class SqrlActionChangePassword;
class SqrlAction;

// Buffer sizes for keys, etc...
#define SQRL_KEY_SIZE 						    32
#define SQRL_SIG_SIZE 						    64

#define SQRL_OPTION_TOKEN_SQRLONLY      "sqrlonly"
#define SQRL_OPTION_TOKEN_HARDLOCK      "hardlock"
#define SQRL_OPTION_TOKEN_CPS                "cps"
#define SQRL_OPTION_TOKEN_SUK                "suk"
#define SQRL_OPTION_TOKEN_SEPARATOR            '~'

#define SQRL_TIF_ID_MATCH 					 0x0001
#define SQRL_TIF_PREVIOUS_ID_MATCH 			 0x0002
#define SQRL_TIF_IP_MATCH 					 0x0004
#define SQRL_TIF_SQRL_DISABLED 				 0x0008
#define SQRL_TIF_FUNCTION_NOT_SUPPORTED 	 0x0010
#define SQRL_TIF_TRANSIENT_ERR 				 0x0020
#define SQRL_TIF_COMMAND_FAILURE 			 0x0040
#define SQRL_TIF_CLIENT_FAILURE 			 0x0080

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

#define SQRL_DEFAULT_ENSCRYPT_SECONDS 		     1
#define SQRL_RESCUE_ENSCRYPT_SECONDS 		     5
#define SQRL_ENTROPY_NEEDED 				   512
#define SQRL_MILLIS_PER_SECOND				  1000
#define SQRL_HINT_ENSCRYPT_MILLISECONDS 	  1000

typedef enum
{
	SQRL_ENCODING_BINARY = 0,
	SQRL_ENCODING_BASE64
} Sqrl_Encoding;

typedef enum
{
	SQRL_EXPORT_ALL = 0,
	SQRL_EXPORT_RESCUE
} Sqrl_Export;

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

typedef unsigned int Sqrl_Tif;

size_t		Sqrl_Version( char *buffer, size_t buffer_len );
uint16_t Sqrl_Version_Major();
uint16_t Sqrl_Version_Minor();
uint16_t Sqrl_Version_Build();
uint16_t Sqrl_Version_Revision();

