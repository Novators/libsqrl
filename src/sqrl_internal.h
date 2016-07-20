/** @file sqrl-internal.h  

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#pragma once

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
extern "C" {
#include "crypto_scrypt.h"
}

#include "sqrl.h"


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

#define SQRL_VERSION_STRING "1"
#define SQRL_KNOWN_VERSIONS_COUNT 1
#define SQRL_CLIENT_VERSIONS {1}

#define FLAG_SET(f,v) f |= v
#define FLAG_CLEAR(f,v) f &= ~(v)
#define FLAG_CHECK(f,v) (v == (f & v))

typedef enum
{
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

typedef enum
{
	SQRL_TRANSACTION_STATUS_SUCCESS = 0,
	SQRL_TRANSACTION_STATUS_FAILED,
	SQRL_TRANSACTION_STATUS_CANCELLED,
	SQRL_TRANSACTION_STATUS_WORKING
} Sqrl_Transaction_Status;


DLL_PUBLIC double sqrl_get_real_time();
DLL_PUBLIC uint64_t sqrl_get_timestamp();

struct Sqrl_Global_Mutices {
	SqrlMutex user;
	SqrlMutex site;
	SqrlMutex transaction;
};

extern struct Sqrl_Global_Mutices SQRL_GLOBAL_MUTICES;

SqrlMutex sqrl_mutex_create();
void sqrl_mutex_destroy(SqrlMutex sm);
bool sqrl_mutex_enter(SqrlMutex sm);
void sqrl_mutex_leave(SqrlMutex sm);

SqrlThread sqrl_thread_create(sqrl_thread_function function, SQRL_THREAD_FUNCTION_INPUT_TYPE input);

struct Sqrl_User_s_callback_data {
	SqrlAction *transaction;
	int adder;
	double multiplier;
	int t1;
	int t2;
	int total;
};

typedef struct Sqrl_Site {
	SqrlAction *transaction;
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

int sqrl_site_count();
void sqrl_client_user_maintenance(bool forceLockAll);

#define BIT_CHECK(v,b) ((v & b) == b)
#define BIT_SET(v,b) v |= b
#define BIT_UNSET(v,b) v &= ~(b)

struct Sqrl_Site_List {
	struct Sqrl_Site *site;
	struct Sqrl_Site_List *next;
};

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

uint16_t readint_16(void *buf);

void sqrl_lcstr(char *);

void bin2rc(char *buf, uint8_t *bin);
void utstring_zero(UT_string *str);

void sqrl_sleep(int sleepMs);
bool sqrl_parse_key_value(char **strPtr, char **keyPtr, char **valPtr,
	size_t *key_len, size_t *val_len, char *sep);
