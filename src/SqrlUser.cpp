/** @file user.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#include <new>
#include "sqrl_internal.h"
#include "SqrlUser.h"
#include "SqrlTransaction.h"
#include "SqrlClient.h"
#include "SqrlCrypt.h"
#include "SqrlEntropy.h"

struct SqrlUserList {
	SqrlUser *user;
	struct SqrlUserList *next;
};

struct SqrlUserList *SQRL_USER_LIST;

int SqrlUser::enscryptCallback( int percent, void *data )
{
	struct Sqrl_User_s_callback_data *cbdata = (struct Sqrl_User_s_callback_data*)data;
	if( cbdata ) {
		int progress = cbdata->adder + (int)((double)percent * cbdata->multiplier);
		if( progress > 100 ) progress = 100;
		if( progress < 0 ) progress = 0;
		if( percent == 100 && progress >= 99 ) progress = 100;
		return SqrlClient::getClient()->callProgress(cbdata->transaction, progress);
	} else {
		return 1;
	}
}

SqrlUser *SqrlUser::create() {
	SqrlUser *user = (SqrlUser*)malloc( sizeof( SqrlUser ) );
	new (user) SqrlUser();
	return user;
}

SqrlUser *SqrlUser::create( const char *buffer, size_t buffer_len ) {
	SqrlUser *user = (SqrlUser*)malloc( sizeof( SqrlUser ) );
	new (user) SqrlUser( buffer, buffer_len );
	return user;
}

SqrlUser *SqrlUser::create( SqrlUri *uri ) {
	SqrlUser *user = (SqrlUser*)malloc( sizeof( SqrlUser ) );
	new (user) SqrlUser();
	return user;
}

void SqrlUser::ensureKeysAllocated()
{
	if( this->keys == NULL ) {
		this->keys = (Sqrl_Keys*)sodium_malloc( sizeof( struct Sqrl_Keys ));
		memset( this->keys, 0, sizeof( struct Sqrl_Keys ));
		BIT_UNSET( this->flags, USER_FLAG_MEMLOCKED );
	}
}

#if defined(DEBUG) && DEBUG_PRINT_USER_COUNT==1
#define PRINT_USER_COUNT(tag) \
int _pucI = 0;\
struct SqrlUserList *_pucC = SQRL_USER_LIST;\
while( _pucC ) {\
	_pucI++;\
	_pucC = _pucC->next;\
}\
printf( "%10s: %d\n", tag, _pucI )
#else
#define PRINT_USER_COUNT(tag)
#endif

SqrlUser* SqrlUser::find( const char *unique_id )
{
	SqrlUser *user = NULL;
	struct SqrlUserList *l;
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
	l = SQRL_USER_LIST;
	while( l ) {
		if( l->user && l->user->uniqueIdMatches( unique_id )) {
			user = l->user;
			user->hold();
			break;
		}
		l = l->next;
	}
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
	return user;
}

void SqrlUser::initialize()
{
	SqrlUser::defaultOptions(&this->options);
	this->referenceCount = 1;
	this->referenceCountMutex = sqrl_mutex_create();
	struct SqrlUserList *l = (struct SqrlUserList*)calloc(1, sizeof(struct SqrlUserList));
	l->user = this;
	sqrl_mutex_enter(SQRL_GLOBAL_MUTICES.user);
	l->next = SQRL_USER_LIST;
	SQRL_USER_LIST = l;
	sqrl_mutex_leave(SQRL_GLOBAL_MUTICES.user);
}

SqrlUser::SqrlUser()
{
	this->initialize();
}

int SqrlUser::countUsers()
{
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
    int i = 0;
    struct SqrlUserList *list = SQRL_USER_LIST;
    while( list ) {
        i++;
        list = list->next;
    }
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
    return i;
}

void SqrlUser::hold()
{
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
	// Make sure the user is still in active memory...
	struct SqrlUserList *c = SQRL_USER_LIST;
	while( c ) {
		if( c->user == this ) {
			sqrl_mutex_enter( this->referenceCountMutex );
			this->referenceCount++;
			sqrl_mutex_leave( this->referenceCountMutex );
			break;
		}
		c = c->next;
	}
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
}

void SqrlUser::release()
{
	bool shouldFreeThis = false;
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
	struct SqrlUserList *list = SQRL_USER_LIST;
	if( list == NULL ) {
		// Not saved in memory... Go ahead and release it.
		sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
		shouldFreeThis = true;
		goto END;
	}
	struct SqrlUserList *prev;
	if( list->user == this ) {
		prev = NULL;
	} else {
		prev = list;
		list = NULL;
		while( prev ) {
			if( prev->next && prev->next->user == this ) {
				list = prev->next;
				break;
			}
			prev = prev->next;
		}
	}
	if( list == NULL ) {
		// Not saved in memory... Go ahead and release it.
		sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
		shouldFreeThis = true;
		goto END;
	}
	// Release this reference
	sqrl_mutex_enter( this->referenceCountMutex );
	this->referenceCount--;

	if( this->referenceCount > 0 ) {
		// There are other references... Do not delete.
		sqrl_mutex_leave( this->referenceCountMutex );
		sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
		goto END;
	}
	// There were no other references... We can delete this.
	shouldFreeThis = true;

	if( prev == NULL ) {
		SQRL_USER_LIST = list->next;
	} else {
		prev->next = list->next;
	}
	free( list );
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );

END:
	if (shouldFreeThis) {
		delete(this);
	}
}

SqrlUser::~SqrlUser() 
{
	if (this->keys != NULL) {
		sodium_mprotect_readwrite(this->keys);
		sodium_free(this->keys);
	}
	sqrl_mutex_destroy(this->referenceCountMutex);
}

void sqrl_client_user_maintenance( bool forceLockAll )
{
	// TODO: Get User Idle Time
	double idleTime = 600;
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.user );
	struct SqrlUserList *list = SQRL_USER_LIST;
	while( list ) {
		if( forceLockAll || idleTime >= list->user->getTimeoutMinutes()) {
			list->user->hintLock();
		}
		list = list->next;
	}
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.user );
}

bool SqrlUser::isMemLocked() 
{
	if( BIT_CHECK( this->flags, USER_FLAG_MEMLOCKED )) {
		return true;
	}
	return false;
}

void SqrlUser::memLock()
{
	if( this->keys != NULL ) {
		sodium_mprotect_noaccess( this->keys );
	}
	BIT_SET( this->flags, USER_FLAG_MEMLOCKED );
}

void SqrlUser::memUnlock()
{
	if( this->keys != NULL ) {
		sodium_mprotect_readwrite( this->keys );
	}
	BIT_UNSET( this->flags, USER_FLAG_MEMLOCKED );
}

bool SqrlUser::isHintLocked()
{
	if( this->hint_iterations == 0 ) return false;
	return true;
}

void SqrlUser::hintLock()
{
	if (this->isHintLocked()) return;
	if( this->keys->password_len == 0 ) {
		return;
	}
	SqrlTransaction *transaction = new SqrlTransaction( SQRL_TRANSACTION_IDENTITY_LOCK );
	transaction->setUser(this);
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

	SqrlCrypt crypt = SqrlCrypt();
	uint8_t iv[12] = {0};
	crypt.plain_text = this->keys->keys[0];
	crypt.text_len = sizeof( struct Sqrl_Keys ) - KEY_SCRATCH_SIZE;
	crypt.salt = this->keys->scratch;
	crypt.iv = iv;
	crypt.tag = this->keys->scratch + 16;
	crypt.cipher_text = this->keys->scratch + 64;
	crypt.add = NULL;
	crypt.add_len = 0;
	crypt.nFactor = SQRL_DEFAULT_N_FACTOR;
	crypt.count = this->options.enscryptSeconds * SQRL_MILLIS_PER_SECOND;
	crypt.flags = SQRL_ENCRYPT | SQRL_MILLIS;

	randombytes_buf( crypt.salt, 16 );
	uint8_t *key = this->keys->scratch + 32;
	size_t password_len = this->options.hintLength;
	if( password_len == 0 || this->keys->password_len < password_len ) {
		password_len = this->keys->password_len;
	}

	if( crypt.genKey( transaction, this->keys->password, password_len ) ) {
		this->hint_iterations = crypt.count;
	}
	if( this->hint_iterations <= 0 ||
		!crypt.doCrypt()) {
		// Encryption failed!
		this->hint_iterations = 0;
		sodium_memzero( this->keys->scratch, KEY_SCRATCH_SIZE );
		goto DONE;
	}

	sodium_memzero( crypt.plain_text, crypt.text_len );
	sodium_memzero( key, SQRL_KEY_SIZE );

DONE:
	transaction->release();
}

void SqrlUser::hintUnlock( SqrlTransaction *transaction, 
				char *hint, 
				size_t length )
{
	if( hint == NULL || length == 0 ) {
		SqrlClient::getClient()->callAuthenticationRequired(transaction, SQRL_CREDENTIAL_HINT);
		return;
	}
	if( !transaction ) return;
	if (transaction->getUser() != this || ! this->isHintLocked()) {
		return;
	}
	struct Sqrl_User_s_callback_data cbdata;
	cbdata.transaction = transaction;
	cbdata.adder = 0;
	cbdata.multiplier = 1;

	SqrlCrypt crypt = SqrlCrypt();
	uint8_t iv[12] = {0};
	crypt.plain_text = this->keys->keys[0];
	crypt.text_len = sizeof( struct Sqrl_Keys ) - KEY_SCRATCH_SIZE;
	crypt.salt = this->keys->scratch;
	crypt.iv = iv;
	crypt.tag = this->keys->scratch + 16;
	crypt.cipher_text = this->keys->scratch + 64;
	crypt.add = NULL;
	crypt.add_len = 0;
	crypt.nFactor = SQRL_DEFAULT_N_FACTOR;
	crypt.count = this->hint_iterations;
	crypt.flags = SQRL_DECRYPT | SQRL_ITERATIONS;

	uint8_t *key = this->keys->scratch + 32;
	if( !crypt.genKey( transaction, hint, length ) ||
		!crypt.doCrypt() ) {
		sodium_memzero( crypt.plain_text, crypt.text_len );
	}
	this->hint_iterations = 0;
	sodium_memzero( key, SQRL_KEY_SIZE );
	sodium_memzero( this->keys->scratch, KEY_SCRATCH_SIZE );
}

bool SqrlUser::_keyGen( SqrlTransaction *transaction, int key_type, uint8_t *key )
{
	if( !transaction ) return false;
	if( transaction->getUser() != this ) {
		return false;
	}
	bool retVal = false;
	int i;
	uint8_t *temp[4];
	int keys[] = {KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3};
	switch( key_type ) {
	case KEY_IUK:
		for( i = 0; i < 4; i++ ) {
			if( this->hasKey( keys[i] )) {
				temp[i] = this->key( transaction, keys[i] );
			} else {
				temp[i] = this->newKey( keys[i] );
			}
		}
		memcpy( temp[3], temp[2], SQRL_KEY_SIZE );
		memcpy( temp[2], temp[1], SQRL_KEY_SIZE );
		memcpy( temp[1], temp[0], SQRL_KEY_SIZE );
		memcpy( temp[0], key, SQRL_KEY_SIZE );
		SqrlEntropy::bytes( key, SQRL_KEY_SIZE );
		retVal = true;
		break;
	case KEY_MK:
		if( this->hasKey( KEY_IUK )) {
			temp[0] = this->key( transaction, KEY_IUK );
			if( temp[0] ) {
				SqrlCrypt::generateMasterKey( key, temp[0] );
				retVal = true;
			}
		}
		break;
	case KEY_ILK:
		temp[0] = this->key( transaction, KEY_IUK );
		if( temp[0] ) {
			SqrlCrypt::generateIdentityLockKey( key, temp[0] );
			retVal = true;
		}
		break;
	case KEY_LOCAL:
		temp[0] = this->key( transaction, KEY_MK );
		if( temp[0] ) {
			SqrlCrypt::generateLocalKey( key, temp[0] );
			retVal = true;
		}
		break;
	case KEY_RESCUE_CODE:
		temp[0] = (uint8_t*)malloc( 512 );
		if( temp[0] ) {
			memset( key, 0, SQRL_KEY_SIZE );
			sodium_mlock( temp[0], 512 );
			SqrlEntropy::get( temp[0], SQRL_ENTROPY_NEEDED );
			bin2rc( (char*)key, temp[0] );
			sodium_munlock( temp[0], 512 );
			free( temp[0] );
			temp[0] = NULL;
			retVal = true;
		}
		break;
	}
	return retVal;
}

bool SqrlUser::regenKeys( SqrlTransaction *transaction )
{
	if( !transaction ) return false;
	if( transaction->getUser() != this ) {
		return false;
	}
	uint8_t *key;
	int keys[] = { KEY_MK, KEY_ILK, KEY_LOCAL };
	int i;
	for( i = 0; i < 3; i++ ) {
		key = this->newKey( keys[i] );
		this->_keyGen( transaction, keys[i], key );
	}
	return true;
}

bool SqrlUser::rekey( SqrlTransaction *transaction )
{
	if( !transaction ) return false;
	if( transaction->getUser() != this ) {
		return false;
	}
	bool retVal = true;
	uint8_t *key;
	if( this->hasKey( KEY_IUK )) {
		key = this->key( transaction, KEY_IUK );
	} else {
		key = this->newKey( KEY_IUK );
	}
	if( ! this->_keyGen( transaction, KEY_IUK, key )) {
		goto ERR;
	}
	key = this->newKey( KEY_RESCUE_CODE );
	if( ! this->_keyGen( transaction, KEY_RESCUE_CODE, key )) {
		goto ERR;
	}
	if( ! this->regenKeys( transaction )) {
		goto ERR;
	}
	this->flags |= (USER_FLAG_T1_CHANGED | USER_FLAG_T2_CHANGED);
	goto DONE;

ERR:
	retVal = false;

DONE:
	return retVal;
}

uint8_t *SqrlUser::newKey( int key_type )
{
	int offset = -1;
	int empty = -1;
	int i = 0;
	for( i = 0; i < USER_MAX_KEYS; i++ ) {
		if( this->lookup[i] == key_type ) {
			offset = i;
		}
		if( this->lookup[i] == 0 ) {
			empty = i;
		}
	}
	if( offset == -1 ) {
		// Not Found
		if( empty > -1 ) {
			// Create new slot
			this->lookup[empty] = key_type;
			offset = empty;
		}
	}
	if( offset ) {
		uint8_t *key = this->keys->keys[offset];
		sodium_memzero( key, SQRL_KEY_SIZE );
		return key;
	}
	return NULL;
}

uint8_t *SqrlUser::key( SqrlTransaction *transaction, int key_type )
{
	if( !transaction ) return NULL;
	if( transaction->getUser() != this ) {
		return NULL;
	}
	int offset, i;
	int loop = -1;
	uint8_t *key;
LOOP:
	loop++;
	if( loop == 3 ) {
		goto DONE;
	}
	offset = -1;
	for( i = 0; i < USER_MAX_KEYS; i++ ) {
		if( this->lookup[i] == key_type ) {
			offset = i;
			break;
		}
	}
	if( offset > -1 ) {
		key = this->keys->keys[offset];
		return key;
	} else {
		// Not Found!
		switch( key_type ) {
		case KEY_RESCUE_CODE:
			// We cannot regenerate this key!
			return NULL;
		case KEY_IUK:
			this->tryLoadRescue(transaction, true);
			goto LOOP;
			break;
		case KEY_MK:
		case KEY_ILK:
		case KEY_PIUK0:
		case KEY_PIUK1:
		case KEY_PIUK2:
		case KEY_PIUK3:
			this->tryLoadPassword(transaction, true);
			goto LOOP;
			break;
		}
	}

DONE:
	return NULL;
}

bool SqrlUser::hasKey( int key_type )
{
	int i;
	for( i = 0; i < USER_MAX_KEYS; i++ ) {
		if( this->lookup[i] == key_type ) {
			return true;
		}
	}
	return false;
}

void SqrlUser::removeKey( int key_type )
{
	int offset = -1;
	int i;
	for( i = 0; i < USER_MAX_KEYS; i++ ) {
		if( this->lookup[i] == key_type ) {
			offset = i;
		}
	}
	if( offset > -1 ) {
		sodium_memzero( this->keys->keys[offset], SQRL_KEY_SIZE );
		this->lookup[offset] = 0;
	}
}

char *SqrlUser::getRescueCode( SqrlTransaction *transaction )
{
	if( !transaction ) return NULL;
	if( transaction->getUser() != this || !this->hasKey( KEY_RESCUE_CODE )) {
		printf( "No key!\n" );
		return NULL;
	}
	char *retVal = (char*)(this->key( transaction, KEY_RESCUE_CODE ));
	return retVal;
}

bool SqrlUser::setRescueCode( char *rc )
{
	if( strlen( rc ) != 24 ) return false;
	int i;
	for( i = 0; i < SQRL_RESCUE_CODE_LENGTH; i++ ) {
		if( rc[i] < '0' || rc[i] > '9' ) {
			return false;
		}
	}
	uint8_t *key = this->newKey( KEY_RESCUE_CODE );
	memcpy( key, rc, SQRL_RESCUE_CODE_LENGTH );
	return true;
}

bool SqrlUser::forceDecrypt( SqrlTransaction *t )
{
	if( !t ) return false;
	if( this->key( t, KEY_MK )) {
		return true;
	}
	return false;
}

bool SqrlUser::forceRescue( SqrlTransaction *t )
{
	if( !t ) return false;
	if( this->key( t, KEY_IUK )) {
		return true;
	}
	return false;
}

size_t SqrlUser::getPasswordLength()
{
	if (this->isHintLocked()) return 0;
	return this->keys->password_len;
}

bool SqrlUser::setPassword( char *password, size_t password_len )
{
	if( this->isHintLocked() ) return false;
	char *p = this->keys->password;
	size_t *l = &this->keys->password_len;
	if( !p || !l ) {
		return false;
	}
	sodium_memzero( p, KEY_PASSWORD_MAX_LEN );
	if( password_len > KEY_PASSWORD_MAX_LEN ) password_len = KEY_PASSWORD_MAX_LEN;
	memcpy( p, password, password_len );
	if( *l > 0 ) {
		// 	Changing password
		BIT_SET(this->flags, USER_FLAG_T1_CHANGED);
	}
	*l = password_len;
	return true;
}

uint8_t *SqrlUser::scratch()
{
	this->ensureKeysAllocated();
	return this->keys->scratch;
}

uint8_t SqrlUser::getHintLength()
{
	uint8_t retVal = 0;
	retVal = this->options.hintLength;
	return retVal;
}

uint8_t SqrlUser::getEnscryptSeconds()
{
	uint8_t retVal = 0;
	retVal = this->options.enscryptSeconds;
	return retVal;
}

uint16_t SqrlUser::getTimeoutMinutes()
{
	uint16_t retVal = 0;
	retVal = this->options.timeoutMinutes;
	return retVal;
}

void SqrlUser::setHintLength( uint8_t length )
{
	this->options.hintLength = length;
	BIT_SET( this->flags, USER_FLAG_T1_CHANGED );
}

void SqrlUser::setEnscryptSeconds( uint8_t seconds )
{
	this->options.enscryptSeconds = seconds;
	BIT_SET( this->flags, USER_FLAG_T1_CHANGED );
}

void SqrlUser::setTimeoutMinutes( uint16_t minutes )
{
	this->options.timeoutMinutes = minutes;
	BIT_SET( this->flags, USER_FLAG_T1_CHANGED );
}

uint16_t SqrlUser::getFlags()
{
	return this->options.flags;
}

uint16_t SqrlUser::checkFlags( uint16_t flags )
{
	uint16_t retVal = 0;
	retVal = this->options.flags & flags;
	return retVal;
}

void SqrlUser::setFlags( uint16_t flags )
{
	if( (this->options.flags & flags) != flags ) {
		this->options.flags |= flags;
		BIT_SET( this->flags, USER_FLAG_T1_CHANGED );
	}
}

void SqrlUser::clearFlags( uint16_t flags )
{
	if( (this->flags & flags) != 0 ) {
		this->options.flags &= ~flags;
		BIT_SET( this->flags, USER_FLAG_T1_CHANGED );
	}
}

void SqrlUser::defaultOptions( Sqrl_User_Options *options ) {
	options->flags = SQRL_DEFAULT_FLAGS;
	options->hintLength = SQRL_DEFAULT_HINT_LENGTH;
	options->enscryptSeconds = SQRL_DEFAULT_ENSCRYPT_SECONDS;
	options->timeoutMinutes = SQRL_DEFAULT_TIMEOUT_MINUTES;
}

bool SqrlUser::getUniqueId( char *buffer )
{
	if( !buffer ) return false;
	strncpy_s( buffer, SQRL_UNIQUE_ID_LENGTH + 1, this->uniqueId, SQRL_UNIQUE_ID_LENGTH );
	return true;
}

bool SqrlUser::uniqueIdMatches( const char *unique_id )
{
	bool retVal = false;
	if( unique_id == NULL ) {
		if( this->uniqueId[0] == 0 ) {
			retVal = true;
		}
	} else {
		if( 0 == strcmp( unique_id, this->uniqueId )) {
			retVal = true;
		}
	}
	return retVal;
}

