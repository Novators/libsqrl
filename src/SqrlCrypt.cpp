/** \file SqrlCrypt.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"

#include "SqrlCrypt.h"
#include "SqrlEnScrypt.h"
#include "SqrlEntropy.h"
#include "aes.h"
#include "gcm.h"
#ifdef ARDUINO
#include <Crypto.h>
#include <SHA256.h>
#include <Ed25519.h>
#include <Curve25519.h>
#endif


#define ENSCRYPT_R 256
#define ENSCRYPT_P 1
#define SODIUM_SCRYPT crypto_pwhash_scryptsalsa208sha256_ll


int SqrlCrypt::enHash( uint64_t *out, const uint64_t *in ) {
	uint64_t trans[4];
	uint64_t tmp[4];
	memset( out, 0, 32 );
	memcpy( tmp, in, 32 );
	int i;
#ifdef ARDUINO
	SHA256 sha = SHA256();
	for( i = 0; i < 16; i++ ) {
		sha.update( tmp, 32 );
		sha.finalize( trans, 32 );
		sha.reset();
		out[0] ^= trans[0];
		out[1] ^= trans[1];
		out[2] ^= trans[2];
		out[3] ^= trans[3];
		memcpy( tmp, trans, 32 );
	}
#else
	sqrl_mlock( trans, 32 );
	sqrl_mlock( tmp, 32 );
	for( i = 0; i < 16; i++ ) {
		crypto_hash_sha256( (unsigned char*)trans, (unsigned char*)tmp, 32 );
		out[0] ^= trans[0];
		out[1] ^= trans[1];
		out[2] ^= trans[2];
		out[3] ^= trans[3];
		memcpy( tmp, trans, 32 );
	}
	sqrl_munlock( trans, 32 );
	sqrl_munlock( tmp, 32 );
#endif
	return 0;
}



int SqrlCrypt::encrypt( uint8_t *cipherText, const uint8_t *plainText, size_t textLength,
	const uint8_t *key, const uint8_t *iv, const uint8_t *add, size_t add_len, uint8_t *tag ) {
	gcm_context ctx;
	uint8_t miv[12] = {0};
	size_t iv_len = 12;
	size_t tag_len = 0;
	int retVal;

	if( iv ) memcpy( miv, iv, iv_len );
	if( tag ) tag_len = 16;
	if( !add ) add_len = 0;

	gcm_setkey( &ctx, (unsigned char*)key, 32 );
	retVal = gcm_crypt_and_tag(
		&ctx, ENCRYPT,
		miv, iv_len,
		add, add_len,
		plainText, cipherText, textLength,
		tag, tag_len );
	gcm_zero_ctx( &ctx );
	return retVal;
}

int SqrlCrypt::decrypt( uint8_t *plainText, const uint8_t *cipherText, size_t textLength,
	const uint8_t *key, const uint8_t *iv, const uint8_t *add, size_t add_len, const uint8_t *tag ) {

	gcm_context ctx;
	size_t iv_len = 0;
	size_t tag_len = 0;
	int retVal;

	if( iv ) iv_len = 12;
	if( tag ) tag_len = 16;
	if( !add ) add_len = 0;

	gcm_setkey( &ctx, (unsigned char*)key, 32 );
	retVal = gcm_auth_decrypt(
		&ctx, iv, iv_len,
		add, add_len,
		cipherText, plainText, textLength,
		tag, tag_len );
	gcm_zero_ctx( &ctx );
	return retVal;

}

bool SqrlCrypt::genKey( SqrlAction *action, const SqrlString *password ) {
	if( !action || !password ) return false;
	if( !this->key || this->count == 0 ) return false;
	size_t salt_len = this->salt ? 16 : 0;
	SqrlString salt( this->salt, salt_len );
	if( (this->flags & SQRL_MILLIS) == SQRL_MILLIS ) {
		SqrlEnScrypt es( NULL, password, &salt, this->count, false, this->nFactor );
		while( !es.isFinished() ) {
			es.update();
		}
		if( !es.isSuccessful() ) return false;
		SqrlString *key = es.getResult();
		memcpy( this->key, key->cdata(), SQRL_KEY_SIZE );
		this->count = es.getIterations();
		this->flags &= ~SQRL_MILLIS;
		this->flags |= SQRL_ITERATIONS;
	} else {
		SqrlEnScrypt es( NULL, password, &salt, this->count, true, this->nFactor );
		while( !es.isFinished() ) {
			es.update();
		}
		if( !es.isSuccessful() ) return false;
		SqrlString *key = es.getResult();
		memcpy( this->key, key->cdata(), SQRL_KEY_SIZE );
		this->count = es.getIterations();
	}
	return true;
}

bool SqrlCrypt::doCrypt() {
	if( !this->cipher_text || !this->plain_text || this->text_len == 0 ||
		!this->key || !this->tag ) return false;
	if( this->flags & SQRL_ENCRYPT ) {
		SqrlCrypt::encrypt( this->cipher_text, this->plain_text, this->text_len,
			key, this->iv, this->add, this->add_len, this->tag );
	} else {
		if( SqrlCrypt::decrypt( this->plain_text, this->cipher_text, this->text_len,
			key, this->iv, this->add, this->add_len, this->tag ) ) {
			return false;
		}
	}
	return true;
}

void SqrlCrypt::generateIdentityLockKey( uint8_t ilk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] ) {
	uint8_t tmp[SQRL_KEY_SIZE];
	sqrl_mlock( tmp, SQRL_KEY_SIZE );
	memcpy( tmp, iuk, SQRL_KEY_SIZE );
	SqrlCrypt::generateCurvePrivateKey( tmp );
	SqrlCrypt::generateCurvePublicKey( ilk, tmp );
	sqrl_munlock( tmp, SQRL_KEY_SIZE );
}

void SqrlCrypt::generateLocalKey( uint8_t local[SQRL_KEY_SIZE], const uint8_t mk[SQRL_KEY_SIZE] ) {
	SqrlCrypt::enHash( (uint64_t*)local, (uint64_t*)mk );
}

void SqrlCrypt::generateMasterKey( uint8_t mk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] ) {
	SqrlCrypt::enHash( (uint64_t*)mk, (uint64_t*)iuk );
}

void SqrlCrypt::generateRandomLockKey( uint8_t rlk[SQRL_KEY_SIZE] ) {
	SqrlEntropy::bytes( rlk, SQRL_KEY_SIZE );
	SqrlCrypt::generateCurvePrivateKey( rlk );
}

void SqrlCrypt::generateServerUnlockKey( uint8_t suk[SQRL_KEY_SIZE], const uint8_t rlk[SQRL_KEY_SIZE] ) {
	SqrlCrypt::generateCurvePublicKey( suk, rlk );
}

void SqrlCrypt::generateVerifyUnlockKey( uint8_t vuk[SQRL_KEY_SIZE], const uint8_t ilk[SQRL_KEY_SIZE], const uint8_t rlk[SQRL_KEY_SIZE] ) {
	uint8_t tmp[SQRL_KEY_SIZE];
	sqrl_mlock( tmp, SQRL_KEY_SIZE );
	SqrlCrypt::generateSharedSecret( tmp, ilk, rlk );
	SqrlCrypt::generatePublicKey( vuk, tmp );
	sqrl_munlock( tmp, SQRL_KEY_SIZE );
}

void SqrlCrypt::generateUnlockRequestSigningKey( uint8_t ursk[SQRL_KEY_SIZE], const uint8_t suk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] ) {
	uint8_t tmp[SQRL_KEY_SIZE];
	sqrl_mlock( tmp, SQRL_KEY_SIZE );
	memcpy( tmp, iuk, SQRL_KEY_SIZE );
	SqrlCrypt::generateCurvePrivateKey( tmp );
	SqrlCrypt::generateSharedSecret( ursk, suk, tmp );
	sqrl_munlock( tmp, SQRL_KEY_SIZE );
}


void SqrlCrypt::generatePublicKey( uint8_t *puk, const uint8_t *prk ) {
#ifdef ARDUINO
	Ed25519::derivePublicKey( puk, prk );
#else
	uint8_t sk[crypto_sign_SECRETKEYBYTES];
	sqrl_mlock( sk, crypto_sign_SECRETKEYBYTES );
	crypto_sign_seed_keypair( puk, sk, prk );
	sqrl_munlock( sk, crypto_sign_SECRETKEYBYTES );
#endif
}


void SqrlCrypt::sign( const SqrlString *msg, const uint8_t sk[32], const uint8_t pk[32], uint8_t sig[64] ) {
#ifdef ARDUINO
	Ed25519::sign( sig, sk, pk, msg->cstring(), msg->length() );
#else
	uint8_t secret[crypto_sign_SECRETKEYBYTES];
	sqrl_mlock( secret, crypto_sign_SECRETKEYBYTES );
	memcpy( secret, sk, 32 );
	memcpy( secret + 32, pk, 32 );
	crypto_sign_detached(
		sig, NULL,
		(const unsigned char*)msg->cdata(), msg->length(),
		secret );
	sqrl_munlock( secret, crypto_sign_SECRETKEYBYTES );
#endif
}


bool SqrlCrypt::verifySignature( const SqrlString *msg, const uint8_t *sig, const uint8_t *pub ) {
#ifdef ARDUINO
	return Ed25519::verify( sig, pub, msg->cstring(), msg->length() );
#else
	if( crypto_sign_verify_detached( sig, (const unsigned char *)msg->cdata(), msg->length(), pub ) == 0 ) {
		return true;
	}
	return false;
#endif
}


void SqrlCrypt::generateCurvePrivateKey( uint8_t *key ) {
	key[0] &= 248;
	key[31] &= 127;
	key[31] |= 64;
}


void SqrlCrypt::generateCurvePublicKey( uint8_t *puk, const uint8_t *prk ) {
#ifdef ARDUINO
	Curve25519::eval( puk, prk, NULL );
#else
	crypto_scalarmult_base( puk, prk );
#endif
}



int SqrlCrypt::generateSharedSecret( uint8_t *shared, const uint8_t *puk, const uint8_t *prk ) {
#ifdef ARDUINO
	Curve25519::eval( shared, puk, prk );
	return 0;
#else
	return crypto_scalarmult( shared, prk, puk );
#endif
}

