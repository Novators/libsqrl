/** @file sqrl-internal.h  

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#ifndef SQRL_INTERNAL_H_INCLUDED
#define SQRL_INTERNAL_H_INCLUDED

#include <stdio.h>
#include <sodium.h>

#include "config.h"
#include "crypto/gcm.h"
#include "sqrl_client.h"
#include "sqrl_server.h"

#define DEBUG_ERROR 1
#define DEBUG_INFO 1
#define DEBUG_CRYPTO 0
#define DEBUG_IDENTITY 0
#define DEBUG_SITE 0

#define DEBUG_PRINTF(t,fmt, ...) \
do {if(DEBUG_PRINT_VAR && t) printf(fmt, __VA_ARGS__); } while(0)
#define DEBUG_PRINT(t,s) \
do {if(DEBUG_PRINT_VAR && t) printf(s); } while( 0 )

#ifdef DEBUG
//#define SQRL_DEBUG_KEYS
#define DEBUG_PRINT_VAR 1

#ifdef SQRL_DEBUG_KEYS
void sqrl_init_key_count();
#endif

#else
#define DEBUG_PRINT_VAR 0
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

typedef int (*enscrypt_progress_fn)(int percent, void* data);
double sqrl_get_real_time( );

typedef struct SqrlMutex SqrlMutex;

typedef struct SqrlMutexMethods 
{
	int (*xGlobalInit)(void);		/* [Optional:] Global mutex initialization */
	void  (*xGlobalRelease)(void);	/* [Optional:] Global Release callback () */
	SqrlMutex * (*xNew)(int);	        /* [Required:] Request a new mutex */
	void  (*xRelease)(SqrlMutex *);	/* [Optional:] Release a mutex  */
	void  (*xEnter)(SqrlMutex *);	    /* [Required:] Enter mutex */
	int (*xTryEnter)(SqrlMutex *);    /* [Optional:] Try to enter a mutex */
	void  (*xLeave)(SqrlMutex *);	    /* [Required:] Leave a locked mutex */
} SqrlMutexMethods;

void sqrlMutexRelease( SqrlMutex *sm );

static SqrlMutexMethods sqrlMutexMethods;

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

struct Sqrl_User_Credentials {
	uint8_t master_key[32];
	uint8_t lock_key[32];
	uint8_t previous_unlock_key[4][32];
};

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
	struct Sqrl_Keys *keys;
};

struct sqrl_user_callback_data {
	sqrl_status_fn *cbfn;
	void * cbdata;
	int adder;
	int divisor;
};

#define SQRL_CAST_USER(a,b) struct Sqrl_User *(a) = (struct Sqrl_User*)(b)
#define RELOCK_START(u,r) sqrl_user_ensure_keys_allocated(u); bool r = sqrl_user_is_memlocked(u); if( r ) { sqrl_user_memunlock(u); }
#define RELOCK_END(u,r) if( r ) {sqrl_user_memlock(u); }

void 		sqrl_user_default_options( Sqrl_User_Options *options );
int sqrl_user_enscrypt_callback( int percent, void *data );
void sqrl_user_ensure_keys_allocated( Sqrl_User u );
uint8_t *sqrl_user_scratch( Sqrl_User user );
bool sqrl_user_regen_keys( Sqrl_User u );
uint8_t *sqrl_user_new_key( Sqrl_User u, int key_type );
uint8_t *sqrl_user_key( Sqrl_User user, int key_type );
void sqrl_user_remove_key( Sqrl_User user, int key_type );
bool sqrl_user_has_key( Sqrl_User user, int key_type );
bool sqrl_user_is_memlocked( Sqrl_User user );
void sqrl_user_memlock( Sqrl_User user );
void sqrl_user_memunlock( Sqrl_User user );
bool sqrl_user_rekey( Sqrl_User u );
char *sqrl_user_password( Sqrl_User user );
size_t *sqrl_user_password_length( Sqrl_User user );
Sqrl_Status sqrl_user_load_with_password(
	Sqrl_User u,
	Sqrl_Storage storage,
	sqrl_status_fn callback,
	void *callback_data );
Sqrl_Status sqrl_user_load_with_rescue_code(
	Sqrl_User u,
	Sqrl_Storage storage,
	sqrl_status_fn callback,
	void *callback_data );
Sqrl_Status sqrl_user_save(
	Sqrl_User user, 
	Sqrl_Storage storage, 
	sqrl_status_fn callback, 
	void *callback_data );


#define BIT_CHECK(v,b) ((v & b) == b)
#define BIT_SET(v,b) v |= b
#define BIT_UNSET(v,b) v &= ~(b)


/* crypt.c */
void 		sqrl_sign( const UT_string *msg, const uint8_t sk[32], const uint8_t pk[32], uint8_t sig[64] );
bool 		sqrl_verify_sig( const UT_string *, const uint8_t *, const uint8_t * );
int 		sqrl_make_shared_secret( uint8_t *, const uint8_t *, const uint8_t * );
//int 		sqrl_make_dh_keys( uint8_t *, uint8_t * );
void 		sqrl_ed_public_key( uint8_t *puk, const uint8_t *prk );
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


int curve25519_donna(uint8_t *, const uint8_t *, const uint8_t *);
void sqrl_generate_random_key( uint8_t *key );

void sqrl_curve_private_key( uint8_t *key );
void sqrl_curve_public_key( uint8_t *puk, const uint8_t *prk );

void sqrl_lcstr( char * );
void printhex( char *label, uint8_t *bin, size_t bin_len );

void sqrl_user_make_hint( Sqrl_Storage storage, const char *password, size_t password_len, uint8_t *plain_text );
void sqrl_user_make_hint_if_needed( Sqrl_Storage storage, const char *password, size_t password_len, uint8_t *plain_text );

void bin2rc( char *buf, uint8_t *bin );

#endif // SQRL_INTERNAL_H_INCLUDED
