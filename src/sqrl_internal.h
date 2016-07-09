/** @file sqrl-internal.h  

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#ifndef SQRL_INTERNAL_H_INCLUDED
#define SQRL_INTERNAL_H_INCLUDED

#include "config.h"

#ifdef UNIX
#include <unistd.h>
#include <pthread.h>
#endif
#ifdef WIN32
#include <Windows.h>
#endif

#include <stdio.h>
#include <sodium.h>
#include "crypto/gcm.h"
#include "sqrl_expert.h"

#define DEBUG_ERR 1
#define DEBUG_INFO 1
#define DEBUG_CRYPTO 0
#define DEBUG_IDENTITY 0
#define DEBUG_SITE 0

/*
#define DEBUG_PRINTF(t,fmt, ...) \
do {if(DEBUG_PRINT_VAR && t) printf(fmt, __VA_ARGS__); } while(0)
#define DEBUG_PRINT(t,s) \
do {if(DEBUG_PRINT_VAR && t) printf(s); } while( 0 )
*/

#ifdef DEBUG
#define DEBUG_PRINT_VAR 1
#define DEBUG_PRINT_USER_COUNT 0
#define DEBUG_PRINT_TRANSACTION_COUNT 0
#define DEBUG_PRINT_CLIENT_PROTOCOL 0
#define DEBUG_PRINT_SERVER_PROTOCOL 0
#define DEBUG_PRINTF(fmt, ...) printf( fmt, __VA_ARGS__)
#define DEBUG_PRINT(s) printf( s );
#else
#define DEBUG_PRINT_VAR 0
#define DEBUG_PRINT_USER_COUNT 0
#define DEBUG_PRINT_TRANSACTION_COUNT 0
#define DEBUG_PRINT_CLIENT_PROTOCOL 0
#define DEBUG_PRINT_SERVER_PROTOCOL 0
#define DEBUG_PRINTF(fmt, ...)
#define DEBUG_PRINT(s) printf( s );
#endif
// Some additional UTstring functions...
#define utstring_shrink(s,l)                          \
do {                                                  \
	s->i -= l;                                        \
	s->d[s->i]='\0';                                  \
} while(0)
	
#define utstring_wipe(s)                              \
do{                                                   \
	if ((s)->d != NULL) sodium_memzero( (s)->d, (s)->n );  \
} while(0)

#define SQRL_ENCRYPT 1
#define SQRL_DECRYPT 0
#define SQRL_MILLIS 2
#define SQRL_ITERATIONS 0

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

#define SQRL_VERSION_STRING "1"
#define SQRL_KNOWN_VERSIONS_COUNT 1
#define SQRL_CLIENT_VERSIONS {1}

#define FLAG_SET(f,v) f |= v
#define FLAG_CLEAR(f,v) f &= ~(v)
#define FLAG_CHECK(f,v) (v == (f & v))


typedef int (*enscrypt_progress_fn)(int percent, void* data);
DLL_PUBLIC double sqrl_get_real_time( );
DLL_PUBLIC uint64_t sqrl_get_timestamp();

typedef void* SqrlMutex;

struct Sqrl_Global_Mutices {
	SqrlMutex user;
	SqrlMutex site;
	SqrlMutex transaction;
};

extern struct Sqrl_Global_Mutices SQRL_GLOBAL_MUTICES;

SqrlMutex sqrl_mutex_create();
void sqrl_mutex_destroy( SqrlMutex sm );
bool sqrl_mutex_enter( SqrlMutex sm );
void sqrl_mutex_leave( SqrlMutex sm );

#ifdef UNIX
typedef pthread_t SqrlThread;
#define SQRL_THREAD_FUNCTION_RETURN_TYPE void*
#define SQRL_THREAD_FUNCTION_INPUT_TYPE void*
#define SQRL_THREAD_LEAVE pthread_exit(NULL)
#endif

#ifdef WIN32
typedef HANDLE SqrlThread;
#define SQRL_THREAD_FUNCTION_RETURN_TYPE DWORD 
#define SQRL_THREAD_FUNCTION_INPUT_TYPE LPVOID
#define SQRL_THREAD_LEAVE ExitThread(0)
#endif

typedef SQRL_THREAD_FUNCTION_RETURN_TYPE (*sqrl_thread_function)(SQRL_THREAD_FUNCTION_INPUT_TYPE data);

SqrlThread sqrl_thread_create( sqrl_thread_function function, SQRL_THREAD_FUNCTION_INPUT_TYPE input );

typedef struct Sqrl_Crypt_Context
{
	uint8_t *plain_text;
	uint8_t *cipher_text;
	size_t text_len;
	uint8_t *add;
	size_t add_len;
	uint8_t *tag;
	uint8_t *salt;
	uint8_t *iv;
	uint32_t count;
	uint8_t nFactor;
	uint8_t flags;
} Sqrl_Crypt_Context;

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

#pragma pack(push,8)
struct Sqrl_Keys
{
	uint8_t keys[USER_MAX_KEYS][SQRL_KEY_SIZE];		//  512   (28 * 32)
	size_t password_len;							//    8
	char password[KEY_PASSWORD_MAX_LEN];			//  512
	// Internal Use Only:
	uint8_t scratch[KEY_SCRATCH_SIZE];				// 2048
													// 3080 bytes
};
#pragma pack(pop)

struct Sqrl_User 
{
	uint8_t lookup[USER_MAX_KEYS];
	uint32_t flags;
	uint32_t hint_iterations;
	Sqrl_User_Options options;
	SqrlMutex referenceCountMutex;
	int referenceCount;
	Sqrl_Storage storage;
	char unique_id[SQRL_UNIQUE_ID_LENGTH+1];
	struct Sqrl_Keys *keys;
};

struct sqrl_user_callback_data {
	Sqrl_Transaction transaction;
	int adder;
	double multiplier;
	int t1;
	int t2;
	int total;
};

struct Sqrl_Transaction {
	Sqrl_Transaction_Type type;
	Sqrl_User user;
	Sqrl_Uri *uri;
	char *string;
	size_t string_len;
	Sqrl_Transaction_Status status;
	char *altIdentity;
	Sqrl_Export exportType;
	Sqrl_Encoding encodingType;
	void *data;
	SqrlMutex mutex;
	int referenceCount;
};

typedef struct Sqrl_Site {
	Sqrl_Transaction *transaction;
	uint16_t userOptFlags;
	uint16_t flags;
	char *serverFriendlyName;
	int version;
	uint32_t tif;
	UT_string *serverString;
	UT_string *clientString;
	uint8_t keys[9][SQRL_KEY_SIZE];
	Sqrl_Transaction_Type currentTransaction;
	int previous_identity;
	double lastAction;
	SqrlMutex mutex;
} Sqrl_Site;



#define SQRL_CAST_TRANSACTION(a,b) struct Sqrl_Transaction *(a) = (struct Sqrl_Transaction*)(b)
#define WITH_TRANSACTION(transaction,t) struct Sqrl_Transaction *transaction = (struct Sqrl_Transaction*)sqrl_transaction_hold( t )
#define END_WITH_TRANSACTION(transaction) sqrl_transaction_release( transaction )

#define SQRL_CAST_USER(a,b) struct Sqrl_User *(a) = (struct Sqrl_User*)(b)
#define WITH_USER(user,u) \
struct Sqrl_User *user = NULL; \
bool wu_relock = false; \
user = (struct Sqrl_User*)sqrl_user_hold(u); \
if( user ) { \
	sqrl_user_ensure_keys_allocated(user); \
	wu_relock = sqrl_user_is_memlocked(user); \
	if( wu_relock ) { \
		sqrl_user_memunlock( user ); \
	} \
}

#define END_WITH_USER(user) \
if( user != NULL ) { \
	if( wu_relock ) { \
		sqrl_user_memlock( user ); \
	} \
	user = sqrl_user_release( (Sqrl_User)(user) ); \
}


DLL_PUBLIC void        sqrl_user_default_options( Sqrl_User_Options *options );
Sqrl_User   sqrl_user_create();
Sqrl_User   sqrl_user_create_from_buffer( const char *buffer, size_t buffer_len );
Sqrl_User   sqrl_user_create_from_file( const char *filename );
int         sqrl_user_enscrypt_callback( int percent, void *data );
void        sqrl_user_ensure_keys_allocated( Sqrl_User u );
bool        sqrl_user_force_decrypt( Sqrl_Transaction transaction );
bool        sqrl_user_force_rescue( Sqrl_Transaction transaction );
bool        sqrl_user_has_key( Sqrl_User user, int key_type );
DLL_PUBLIC void        sqrl_user_hintlock( Sqrl_User user );
DLL_PUBLIC void        sqrl_user_hintunlock(
                Sqrl_Transaction transaction, 
				char *hint, 
				size_t length );
DLL_PUBLIC bool        sqrl_user_is_hintlocked( Sqrl_User user );
bool        sqrl_user_is_memlocked( Sqrl_User user );
uint8_t*    sqrl_user_key( Sqrl_Transaction transaction, int key_type );
bool        sqrl_user_try_load_password( Sqrl_Transaction transaction, bool retry );
bool        sqrl_user_try_load_rescue( Sqrl_Transaction transaction, bool retry );
void        sqrl_user_memlock( Sqrl_User user );
void        sqrl_user_memunlock( Sqrl_User user );
uint8_t*    sqrl_user_new_key( Sqrl_User u, int key_type );
bool        sqrl_user_regen_keys( Sqrl_Transaction transaction );
bool        sqrl_user_rekey( Sqrl_Transaction transaction );
void        sqrl_user_remove_key( Sqrl_User user, int key_type );
bool        sqrl_user_save( Sqrl_Transaction transaction );
bool        sqrl_user_save_to_buffer( Sqrl_Transaction transaction );
uint8_t*    sqrl_user_scratch( Sqrl_User user );
DLL_PUBLIC bool        sqrl_user_set_password(
				Sqrl_User u, 
				char *password, 
				size_t password_len );
bool        sqrl_user_update_storage( Sqrl_Transaction transaction );

Sqrl_Transaction sqrl_transaction_create( Sqrl_Transaction_Type type );
Sqrl_Transaction sqrl_transaction_hold( Sqrl_Transaction t );
Sqrl_Transaction sqrl_transaction_release( Sqrl_Transaction t );
void sqrl_transaction_set_user( Sqrl_Transaction t, Sqrl_User u );
int sqrl_transaction_count();
int sqrl_user_count();
int sqrl_site_count();
void sqrl_client_user_maintenance( bool forceLockAll );

#define BIT_CHECK(v,b) ((v & b) == b)
#define BIT_SET(v,b) v |= b
#define BIT_UNSET(v,b) v &= ~(b)

struct Sqrl_User_List {
	struct Sqrl_User *user;
	struct Sqrl_User_List *next;
};

struct Sqrl_Site_List {
	struct Sqrl_Site *site;
	struct Sqrl_Site_List *next;
};

struct Sqrl_Transaction_List {
	struct Sqrl_Transaction *transaction;
	struct Sqrl_Transaction_List *next;
};

extern struct Sqrl_Client_Callbacks *SQRL_CLIENT_CALLBACKS;

Sqrl_User sqrl_client_call_select_user( 
	Sqrl_Transaction transaction );
void sqrl_client_call_select_alternate_identity( 
	Sqrl_Transaction transaction );
bool sqrl_client_call_authentication_required( 
	Sqrl_Transaction transaction, 
	Sqrl_Credential_Type credentialType );
void sqrl_client_call_ask(
	Sqrl_Transaction transaction,
	const char *message, size_t message_len,
	const char *firstButton, size_t firstButton_len,
	const char *secondButton, size_t secondButton_len );
void sqrl_client_call_send(
	Sqrl_Transaction transaction,
	const char *url, size_t url_len,
	const char *payload, size_t payload_len );
int sqrl_client_call_progress(
	Sqrl_Transaction transaction,
	int progress );
void sqrl_client_call_save_suggested(
	Sqrl_User user);
void sqrl_client_call_transaction_complete(
	Sqrl_Transaction transaction );


bool sqrl_client_require_password( Sqrl_Transaction transaction );
bool sqrl_client_require_hint( Sqrl_Transaction transaction );
bool sqrl_client_require_rescue_code( Sqrl_Transaction transaction );

#define SITE_KEY_LOOKUP 0
#define SITE_KEY_SEC 1
#define SITE_KEY_PUB 2
#define SITE_KEY_PSEC 3
#define SITE_KEY_PPUB 4
#define SITE_KEY_SUK 5
#define SITE_KEY_VUK 6
#define SITE_KEY_URSK 7
#define SITE_KEY_URPK 8

// Site information saved for 5 minutes (600 seconds) past last action
#define SQRL_CLIENT_SITE_TIMEOUT 600

Sqrl_Transaction_Status sqrl_client_resume_transaction( Sqrl_Transaction t, const char *response, size_t response_len );
void sqrl_client_site_maintenance( bool forceDeleteAll );

/* crypt.c */
DLL_PUBLIC void 		sqrl_sign( const UT_string *msg, const uint8_t sk[32], const uint8_t pk[32], uint8_t sig[64] );
DLL_PUBLIC bool 		sqrl_verify_sig( const UT_string *, const uint8_t *, const uint8_t * );
DLL_PUBLIC int 		sqrl_make_shared_secret( uint8_t *, const uint8_t *, const uint8_t * );
//int 		sqrl_make_dh_keys( uint8_t *, uint8_t * );
DLL_PUBLIC void 		sqrl_ed_public_key( uint8_t *puk, const uint8_t *prk );
bool 		sqrl_crypt( Sqrl_Crypt_Context *sctx, const char *password, size_t password_len, enscrypt_progress_fn callback, void * callback_data );
bool 		sqrl_crypt_gcm( Sqrl_Crypt_Context *sctx, uint8_t *key );
uint32_t 	sqrl_crypt_enscrypt( Sqrl_Crypt_Context *sctx, uint8_t *key, const char *password, size_t password_len, enscrypt_progress_fn callback, void * callback_data );

void sqrl_gen_ilk( uint8_t ilk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] );
void sqrl_gen_local( uint8_t local[SQRL_KEY_SIZE], const uint8_t mk[SQRL_KEY_SIZE] );
void sqrl_gen_mk( uint8_t mk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] );
void sqrl_gen_rlk( uint8_t rlk[SQRL_KEY_SIZE] );
void sqrl_gen_suk( uint8_t suk[SQRL_KEY_SIZE], const uint8_t rlk[SQRL_KEY_SIZE] );
void sqrl_gen_vuk( uint8_t vuk[SQRL_KEY_SIZE], const uint8_t ilk[SQRL_KEY_SIZE], const uint8_t rlk[SQRL_KEY_SIZE] );
void sqrl_gen_ursk( uint8_t ursk[SQRL_KEY_SIZE], const uint8_t suk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] );


uint16_t readint_16( void *buf );
int Sqrl_EnHash( uint64_t *out, uint64_t *in );

int sqrl_enscrypt( 
	uint8_t *buf, 
	const char *password, 
	size_t password_len, 
	const uint8_t *salt, 
	uint8_t salt_len,
	uint8_t nFactor,
	uint16_t iterations,
	enscrypt_progress_fn cb_ptr, 
	void *cb_data );
int sqrl_enscrypt_ms( 
	uint8_t *buf, 
	const char *password, 
	size_t password_len, 
	const uint8_t *salt, 
	uint8_t salt_len,
	uint8_t nFactor,
	int millis,
	enscrypt_progress_fn cb_ptr, 
	void *cb_data );

DLL_PUBLIC void sqrl_curve_private_key( uint8_t *key );
DLL_PUBLIC void sqrl_curve_public_key( uint8_t *puk, const uint8_t *prk );

void sqrl_lcstr( char * );

void bin2rc( char *buf, uint8_t *bin );
DLL_PUBLIC void utstring_zero( UT_string *str );

void sqrl_sleep(int sleepMs);
bool sqrl_parse_key_value( char **strPtr, char **keyPtr, char **valPtr,
    size_t *key_len, size_t *val_len, char *sep );


#endif // SQRL_INTERNAL_H_INCLUDED
