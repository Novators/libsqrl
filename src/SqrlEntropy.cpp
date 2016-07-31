#include "sqrl_internal.h"
#include "SqrlEntropy.h"
#include "sodium.h"
#include "rdrand.h"
#include <mutex>

#define SQRL_ENTROPY_REPEAT_FAST 9
#define SQRL_ENTROPY_REPEAT_SLOW 190
#define SQRL_ENTROPY_TARGET 512

void *SqrlEntropy::state = NULL;
int SqrlEntropy::estimated_entropy = 0;
int SqrlEntropy::entropy_target = SQRL_ENTROPY_TARGET;
bool SqrlEntropy::initialized = false;
bool SqrlEntropy::stopping = false;
int SqrlEntropy::sleeptime = SQRL_ENTROPY_REPEAT_FAST;
std::mutex *SqrlEntropy::mutex = NULL;
std::thread *SqrlEntropy::thread = NULL;


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

void SqrlEntropy::update() {
	if( !SqrlEntropy::state ) return;
	struct sqrl_fast_flux_entropy ffe;
	sqrl_store_fast_flux_entropy( &ffe );
	SqrlEntropy::mutex->lock();
	crypto_hash_sha512_update( 
		(crypto_hash_sha512_state*)SqrlEntropy::state, 
		(unsigned char*)&ffe, 
		sizeof( struct sqrl_fast_flux_entropy ) );
	if( ++(SqrlEntropy::estimated_entropy) >= SqrlEntropy::entropy_target ) {
		SqrlEntropy::sleeptime = SQRL_ENTROPY_REPEAT_SLOW;
	}
	SqrlEntropy::mutex->unlock();
}

void
SqrlEntropy::threadFunction() {
	struct sqrl_entropy_pool *pool = (struct sqrl_entropy_pool*)SqrlEntropy::state;

	while( !SqrlEntropy::stopping ) {
		SqrlEntropy::update();
		sqrl_sleep( SqrlEntropy::sleeptime );
	}
	SqrlEntropy::mutex->lock();
	SqrlEntropy::estimated_entropy = 0;
	SqrlEntropy::initialized = false;
	free( SqrlEntropy::state );
	SqrlEntropy::state = NULL;
	delete SqrlEntropy::mutex;
	SqrlEntropy::mutex = NULL;
	delete SqrlEntropy::thread;
	SqrlEntropy::thread = NULL;
}

void SqrlEntropy::start() {
	if( SqrlEntropy::state ) return;
	SqrlEntropy::initialized = true;
	SqrlEntropy::stopping = false;
	SqrlEntropy::estimated_entropy = 0;
	SqrlEntropy::entropy_target = SQRL_ENTROPY_TARGET;
	SqrlEntropy::sleeptime = SQRL_ENTROPY_REPEAT_FAST;

	SqrlEntropy::state = calloc( 1, sizeof( crypto_hash_sha512_state ) );
	SqrlEntropy::mutex = new std::mutex();
	crypto_hash_sha512_init( (crypto_hash_sha512_state*)SqrlEntropy::state );
	SqrlEntropy::addBracket( NULL );
	SqrlEntropy::thread = new std::thread( SqrlEntropy::threadFunction );
	SqrlEntropy::thread->detach();
	while( SqrlEntropy::estimated_entropy == 0 ) {
		sqrl_sleep( 5 );
	}
}

void SqrlEntropy::stop() {
	if( !SqrlEntropy::state ) return;
	SqrlEntropy::stopping = true;
	while( SqrlEntropy::thread ) {
		sqrl_sleep( 5 );
	}
}

void SqrlEntropy::increment( int amount ) {
	SqrlEntropy::estimated_entropy += amount;
	if( SqrlEntropy::estimated_entropy >= SqrlEntropy::entropy_target ) {
		SqrlEntropy::sleeptime = SQRL_ENTROPY_REPEAT_SLOW;
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
void SqrlEntropy::add( uint8_t* msg, size_t msg_len ) {
	if( !SqrlEntropy::state ) SqrlEntropy::start();
	struct sqrl_entropy_pool *pool = (struct sqrl_entropy_pool*)SqrlEntropy::state;
	if( SqrlEntropy::initialized ) {
		SqrlEntropy::mutex->lock();
		if( SqrlEntropy::initialized ) {
			struct sqrl_fast_flux_entropy ffe;
			sqrl_store_fast_flux_entropy( &ffe );
			uint8_t *buf = (uint8_t*)malloc( msg_len + sizeof( struct sqrl_fast_flux_entropy ) );
			if( buf ) {
				memcpy( buf, msg, msg_len );
				memcpy( buf + msg_len, &ffe, sizeof( struct sqrl_fast_flux_entropy ) );
				crypto_hash_sha512_update( (crypto_hash_sha512_state*)SqrlEntropy::state, (unsigned char*)buf, sizeof( buf ) );
				SqrlEntropy::estimated_entropy += (1 + ((int)msg_len / 64));
				if( SqrlEntropy::estimated_entropy >= SqrlEntropy::entropy_target ) {
					SqrlEntropy::sleeptime = SQRL_ENTROPY_REPEAT_SLOW;
				}
				free( buf );
			}
		}
		SqrlEntropy::mutex->unlock();
	}
}

/**
* Gets a chunk of entropy, and resets the avaliable entropy counter.  Blocks until \p desired_entropy is available.
*
* @param buf A buffer to receive the entropy.  Must be at least 512 bits (64 bytes) long.
* @param desired_entropy The minimum amount of estimated entropy required.
* @return The actual amount of estimated entropy.
*/

int SqrlEntropy::get( uint8_t *buf, int desired_entropy, bool blocking ) {
	if( !SqrlEntropy::state ) SqrlEntropy::start();
	struct sqrl_entropy_pool *pool = (struct sqrl_entropy_pool*)SqrlEntropy::state;

	int received_entropy = 0;
START:
	if( !SqrlEntropy::initialized ) return 0;
	SqrlEntropy::entropy_target = desired_entropy;
	if( blocking ) {
		while( SqrlEntropy::estimated_entropy < desired_entropy ) {
			sqrl_sleep( SQRL_ENTROPY_REPEAT_SLOW );
		}
	} else {
		if( SqrlEntropy::estimated_entropy < desired_entropy ) {
			SqrlEntropy::entropy_target = desired_entropy;
			SqrlEntropy::sleeptime = SQRL_ENTROPY_REPEAT_FAST;
		}
		return 0;
	}
	if( SqrlEntropy::initialized &&
		SqrlEntropy::estimated_entropy >= desired_entropy ) {
		SqrlEntropy::mutex->lock();
		if( SqrlEntropy::initialized &&
			SqrlEntropy::estimated_entropy >= desired_entropy ) {
			SqrlEntropy::addBracket( NULL );
			crypto_hash_sha512_final( (crypto_hash_sha512_state*)SqrlEntropy::state, buf );
			crypto_hash_sha512_init( (crypto_hash_sha512_state*)SqrlEntropy::state );
			SqrlEntropy::addBracket( buf );
			received_entropy = SqrlEntropy::estimated_entropy;
			SqrlEntropy::estimated_entropy = 0;
		} else {
			SqrlEntropy::mutex->unlock();
			goto START;
		}
		SqrlEntropy::mutex->unlock();
	} else {
		goto START;
	}
	SqrlEntropy::entropy_target = SQRL_ENTROPY_TARGET;
	SqrlEntropy::sleeptime = SQRL_ENTROPY_REPEAT_FAST;
	return received_entropy;
}


int SqrlEntropy::bytes( uint8_t* buf, int nBytes ) {
	if( !buf || (nBytes <= 0) ) return 0;

	int desired_entropy = (nBytes > 64) ? (8 * 64) : (8 * nBytes);
	if( desired_entropy > SQRL_ENTROPY_NEEDED ) desired_entropy = SQRL_ENTROPY_NEEDED;
	uint8_t tmp[64];
	sodium_mlock( tmp, 64 );
	SqrlEntropy::get( tmp, desired_entropy, true );

	if( nBytes <= 64 ) {
		memcpy( buf, tmp, nBytes );
	} else {
		crypto_stream_chacha20( (unsigned char*)buf, nBytes, tmp, (tmp + crypto_stream_chacha20_NONCEBYTES) );
	}

	sodium_munlock( tmp, 64 );
	return nBytes;
}


/**
* Gets the estimated amount of entropy available in the entropy collection pool.
*
* Estimated entropy is not an exact measurement.  It is incremented when additional entropy is collected.  We conservatively assume that each entropy collection contains AT LEAST on bit of real entropy.
*
* @return The estimated entropy (bits) available
*/

int SqrlEntropy::estimate() {
	if( !SqrlEntropy::state ) SqrlEntropy::start();
	if( SqrlEntropy::initialized ) {
		return SqrlEntropy::estimated_entropy;
	}
	return 0;
}

