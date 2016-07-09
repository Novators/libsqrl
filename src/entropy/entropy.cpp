/** @file entropy.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

// fast ~= 50 times per second
// slow ~= 5 times per second
// Depending on processor speed.
/*
#define SQRL_NIX_ENTROPY_REPEAT_FAST 9000000
#define SQRL_NIX_ENTROPY_REPEAT_SLOW 190000000
#define SQRL_WIN_ENTROPY_REPEAT_FAST 9
#define SQRL_WIN_ENTROPY_REPEAT_SLOW 190
*/
#define SQRL_ENTROPY_REPEAT_FAST 9
#define SQRL_ENTROPY_REPEAT_SLOW 190
#define SQRL_ENTROPY_TARGET 512

#include <sodium.h>

#include "rdrand.h"
#include "../sqrl_internal.h"



struct sqrl_entropy_pool
{
	crypto_hash_sha512_state state;
	int estimated_entropy;
	int entropy_target;
	bool initialized;
	bool stopping;
	int sleeptime;
	SqrlMutex mutex;
	SqrlThread thread;
};

#if defined(__MACH__)
#include "entropy_mac.h"
#elif defined(_WIN32)
#include "entropy_win.h"
#else
#include "entropy_linux.h"
#endif

struct sqrl_entropy_message
{
	uint8_t *msg;
	struct sqrl_fast_flux_entropy ffe;
};

static struct sqrl_entropy_pool *sqrl_entropy_get_pool();
static void sqrl_increment_entropy( struct sqrl_entropy_pool *pool, int amount );


static void sqrl_entropy_update()
{
	struct sqrl_entropy_pool *pool = sqrl_entropy_get_pool();
	struct sqrl_fast_flux_entropy ffe;
	sqrl_store_fast_flux_entropy( &ffe );
	sqrl_mutex_enter(pool->mutex);
	crypto_hash_sha512_update( &pool->state, (unsigned char*)&ffe, sizeof( struct sqrl_fast_flux_entropy ));
	sqrl_increment_entropy( pool, 1 );
	sqrl_mutex_leave(pool->mutex);
}

SQRL_THREAD_FUNCTION_RETURN_TYPE
sqrl_entropy_thread( SQRL_THREAD_FUNCTION_INPUT_TYPE input )
{
	struct sqrl_entropy_pool *pool = (struct sqrl_entropy_pool*)input;

	while( !pool->stopping ) {
		sqrl_entropy_update();
		sqrl_sleep( pool->sleeptime );
	}
	sqrl_mutex_enter(pool->mutex);
	pool->estimated_entropy = 0;
	pool->initialized = false;
	sqrl_mutex_leave(pool->mutex);
	SQRL_THREAD_LEAVE;
}

static struct sqrl_entropy_pool *sqrl_entropy_create()
{
	struct sqrl_entropy_pool *pool = (struct sqrl_entropy_pool*)malloc( sizeof( struct sqrl_entropy_pool ));
	if( !pool ) {
		return NULL;
	}
	pool->initialized = true;
	pool->stopping = false;
	pool->estimated_entropy = 0;
	pool->entropy_target = SQRL_ENTROPY_TARGET;
	pool->sleeptime = SQRL_ENTROPY_REPEAT_FAST;

	crypto_hash_sha512_init( &pool->state );
	sqrl_add_entropy_bracket( pool, NULL );
	pool->mutex = sqrl_mutex_create();
	pool->thread = sqrl_thread_create( sqrl_entropy_thread, (SQRL_THREAD_FUNCTION_INPUT_TYPE)pool );
	return pool;	
}

static struct sqrl_entropy_pool *_public_pool = NULL;

static struct sqrl_entropy_pool *sqrl_entropy_get_pool()
{
	if( _public_pool == NULL ) {
		_public_pool = sqrl_entropy_create();
	}
	return _public_pool;
}


static void sqrl_increment_entropy( struct sqrl_entropy_pool *pool, int amount ) {
	pool->estimated_entropy += amount;
	if( pool->estimated_entropy >= pool->entropy_target ) {
		pool->sleeptime = SQRL_ENTROPY_REPEAT_SLOW;
	}
}

/**
 * Collects additional entropy.
 *
 * Available entropy is increased by (1 + (\p msg_len / 64))
 *
 * @param msg A chunk of data to be added to the pool
 * @param msg_len The length of \p msg (in bytes)
 */

void sqrl_entropy_add( uint8_t* msg, size_t msg_len )
{
	struct sqrl_entropy_pool *pool = sqrl_entropy_get_pool();
	if( pool->initialized ) {
		sqrl_mutex_enter(pool->mutex);
		if( pool->initialized ) {
			struct sqrl_fast_flux_entropy ffe;
			sqrl_store_fast_flux_entropy( &ffe );
			uint8_t *buf = (uint8_t*)malloc( msg_len + sizeof( struct sqrl_fast_flux_entropy ));
			if( buf ) {
				memcpy( buf, msg, msg_len );
				memcpy( buf+msg_len, &ffe, sizeof( struct sqrl_fast_flux_entropy ));
				crypto_hash_sha512_update( &pool->state, (unsigned char*)buf, sizeof( buf ));
				sqrl_increment_entropy( pool, 1 + (msg_len / 64) );
				free( buf );
			}
		}
		sqrl_mutex_leave(pool->mutex);
	}
}

/**
 * Gets a chunk of entropy, and resets the avaliable entropy counter.  Blocks until \p desired_entropy is available.
 * 
 * @param buf A buffer to receive the entropy.  Must be at least 512 bits (64 bytes) long.
 * @param desired_entropy The minimum amount of estimated entropy required.
 * @return The actual amount of estimated entropy.
 */

int sqrl_entropy_get_blocking( uint8_t *buf, int desired_entropy ) 
{
	struct sqrl_entropy_pool *pool = sqrl_entropy_get_pool();

	int received_entropy = 0;
START:
	if( !pool->initialized ) return 0;
	pool->entropy_target = desired_entropy;
	while( pool->estimated_entropy < desired_entropy ) {
		sqrl_sleep( SQRL_ENTROPY_REPEAT_SLOW );
	}
	if( pool->initialized &&
		pool->estimated_entropy >= desired_entropy ) {
		sqrl_mutex_enter(pool->mutex);
		if( pool->initialized &&
			pool->estimated_entropy >= desired_entropy ) {
			sqrl_add_entropy_bracket( pool, NULL );
			crypto_hash_sha512_final( &pool->state, buf );
			crypto_hash_sha512_init( &pool->state );
			sqrl_add_entropy_bracket( pool, buf );
			received_entropy = pool->estimated_entropy;
			pool->estimated_entropy = 0;
		} else {
			sqrl_mutex_leave(pool->mutex);
			goto START;
		}
		sqrl_mutex_leave(pool->mutex);
	} else{
		goto START;
	}
	pool->entropy_target = SQRL_ENTROPY_TARGET;
	pool->sleeptime = SQRL_ENTROPY_REPEAT_FAST;
	return received_entropy;
}


int sqrl_entropy_bytes( uint8_t* buf, int nBytes )
{
	if( !buf || (nBytes <= 0) ) return 0;

	int desired_entropy = (nBytes > 64) ? (8*64) : (8*nBytes);
	if( desired_entropy > SQRL_ENTROPY_NEEDED ) desired_entropy = SQRL_ENTROPY_NEEDED;
	uint8_t tmp[64];
	sodium_mlock( tmp, 64 );
	sqrl_entropy_get_blocking( tmp, desired_entropy );

	if( nBytes <= 64 ) {
		memcpy( buf, tmp, nBytes );
	} else {
		crypto_stream_chacha20( (unsigned char*)buf, nBytes, tmp, (tmp + crypto_stream_chacha20_NONCEBYTES) );
	}

	sodium_munlock( tmp, 64 );
	return nBytes;
}

/**
 * Gets a chunk of entropy, and resets the avaliable entropy counter.
 * 
 * @warning You MUST check the return value before attempting to use \p buf.  If this function returns 0, the buf has NOT been modified, and cannot be trusted as entropy!
 *
 * @param buf A buffer to receive the entropy.  Must be at least 512 bits (64 bytes) long.
 * @param desired_entropy The minimum amount of estimated entropy required.
 * @return The actual amount of estimated entropy.  If \p desired_entropy is not available, returns 0.
 */

int sqrl_entropy_get( uint8_t* buf, int desired_entropy )
{
	struct sqrl_entropy_pool *pool = sqrl_entropy_get_pool();
	int received_entropy = 0;
	if( pool->initialized &&
		pool->estimated_entropy >= desired_entropy ) {
		sqrl_mutex_enter(pool->mutex);
		if( pool->initialized &&
			pool->estimated_entropy >= desired_entropy ) {
			sqrl_add_entropy_bracket( pool, NULL );
			crypto_hash_sha512_final( &pool->state, buf );
			crypto_hash_sha512_init( &pool->state );
			sqrl_add_entropy_bracket( pool, buf );
			received_entropy = pool->estimated_entropy;
			pool->estimated_entropy = 0;
		}
		sqrl_mutex_leave(pool->mutex);
	}
	if( pool->estimated_entropy < desired_entropy ) {
		pool->entropy_target = desired_entropy;
	}
	pool->sleeptime = SQRL_ENTROPY_REPEAT_FAST;
	return received_entropy;
}

/**
 * Gets the estimated amount of entropy available in the entropy collection pool.
 *
 * Estimated entropy is not an exact measurement.  It is incremented when additional entropy is collected.  We conservatively assume that each entropy collection contains AT LEAST on bit of real entropy.
 * 
 * @return The estimated entropy (bits) available
 */

int sqrl_entropy_estimate()
{
	struct sqrl_entropy_pool *pool = sqrl_entropy_get_pool();
	if( pool->initialized ) {
		return pool->estimated_entropy;
	}
	return 0;
}

