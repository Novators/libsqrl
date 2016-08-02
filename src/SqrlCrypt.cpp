#include "sqrl_internal.h"

#include "SqrlCrypt.h"
#include "SqrlEntropy.h"
#include "aes.h"
#include "gcm.h"


#define ENSCRYPT_R 256
#define ENSCRYPT_P 1
#define SODIUM_SCRYPT crypto_pwhash_scryptsalsa208sha256_ll


int SqrlCrypt::enHash( uint64_t *out, const uint64_t *in ) {
	uint64_t trans[4];
	uint64_t tmp[4];
	sqrl_mlock( trans, 32 );
	sqrl_mlock( tmp, 32 );
	memset( out, 0, 32 );
	memcpy( tmp, in, 32 );
	int i;
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

bool SqrlCrypt::genKey( SqrlAction *action, const char *password, size_t password_len ) {
	if( !action || !password ) return false;
	if( !this->key || this->count == 0 ) return false;
	size_t salt_len = this->salt ? 16 : 0;
	uint32_t newCount;
	if( (this->flags & SQRL_MILLIS) == SQRL_MILLIS ) {
		newCount = SqrlCrypt::enScryptMillis( NULL, this->key, password, password_len, this->salt, (uint8_t)salt_len, this->count, this->nFactor );
		if( newCount == -1 ) return false;
		this->count = newCount;
		this->flags &= ~SQRL_MILLIS;
		this->flags |= SQRL_ITERATIONS;
	} else {
		newCount = SqrlCrypt::enScrypt( NULL, this->key, password, password_len, this->salt, (uint8_t)salt_len, this->count, this->nFactor );
		if( newCount == -1 ) return false;
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

int SqrlCrypt::enScrypt( SqrlAction *action,
	uint8_t *buf, const char *password, size_t password_len,
	const uint8_t *salt, uint8_t salt_len,
	uint16_t iterations, uint8_t nFactor ) {
#ifdef ARDUINO
	crypto_hash_sha256( (unsigned char*)buf, (const unsigned char*)password, password_len );
#else
	if( !buf ) return -1;
	uint64_t N = (((uint64_t)1) << nFactor);
	uint8_t t[2][32] = {{0}, {0}};
	double startTime, endTime;
	int i = 1, p = 0, lp = -1;

	escrypt_kdf_t   escrypt_kdf;
	escrypt_local_t local;
	int             retVal;

	if( escrypt_init_local( &local ) ) {
		return -1; /* LCOV_EXCL_LINE */
	}
	escrypt_kdf = sodium_runtime_has_sse2() ? escrypt_kdf_sse : escrypt_kdf_nosse;

	startTime = sqrl_get_real_time();

	retVal = escrypt_kdf( &local, (uint8_t*)password, password_len, salt, salt_len, N, ENSCRYPT_R, ENSCRYPT_P, t[1], 32 );
	if( retVal != 0 ) {
		goto DONE;
	}
	memcpy( buf, t[1], 32 );
	while( i < iterations ) {
		/*
		if( cb_ptr ) {
			if( lp != (p = (int)((double)i / iterations * 100)) ) {
				if( 0 == (*cb_ptr)(p, cb_data) ) {
					retVal = -1;
					break;
				}
				lp = p;
			}
		}
		*/
		if( i & 1 ) {
			retVal = escrypt_kdf( &local, (uint8_t*)password, password_len, t[1], 32, N, ENSCRYPT_R, ENSCRYPT_P, t[0], 32 );
			((uint64_t*)buf)[0] ^= ((uint64_t*)t[0])[0];
			((uint64_t*)buf)[1] ^= ((uint64_t*)t[0])[1];
			((uint64_t*)buf)[2] ^= ((uint64_t*)t[0])[2];
			((uint64_t*)buf)[3] ^= ((uint64_t*)t[0])[3];
		} else {
			retVal = escrypt_kdf( &local, (uint8_t*)password, password_len, t[0], 32, N, ENSCRYPT_R, ENSCRYPT_P, t[1], 32 );
			((uint64_t*)buf)[0] ^= ((uint64_t*)t[1])[0];
			((uint64_t*)buf)[1] ^= ((uint64_t*)t[1])[1];
			((uint64_t*)buf)[2] ^= ((uint64_t*)t[1])[2];
			((uint64_t*)buf)[3] ^= ((uint64_t*)t[1])[3];
		}
		i++;
		if( retVal != 0 ) goto DONE;
	}

DONE:
	endTime = (sqrl_get_real_time() - startTime) * 1000;
	//if( cb_ptr ) (*cb_ptr)(100, cb_data);

	if( retVal != 0 ) {
		sqrl_memzero( buf, 32 );
	}
	if( escrypt_free_local( &local ) ) {
		return -1; /* LCOV_EXCL_LINE */
	}
	return retVal == 0 ? (int)endTime : -1;
#endif
}

int SqrlCrypt::enScryptMillis( SqrlAction *action,
	uint8_t *buf, const char *password, size_t password_len,
	const uint8_t *salt, uint8_t salt_len,
	int millis, uint8_t nFactor ) {
#ifdef ARDUINO
	crypto_hash_sha256( (unsigned char*)buf, (const unsigned char*)password, password_len );
#else
	if( !buf ) return -1;
	uint64_t N = (((uint64_t)1) << nFactor);
	uint8_t t[2][32] = {{0}, {0}};
	int i = 1;
	int p = 0, lp = -1;
	double startTime, elapsed = 0.0;

	escrypt_kdf_t   escrypt_kdf;
	escrypt_local_t local;
	int             retVal;

	if( escrypt_init_local( &local ) ) {
		return -1; /* LCOV_EXCL_LINE */
	}
	escrypt_kdf = sodium_runtime_has_sse2() ? escrypt_kdf_sse : escrypt_kdf_nosse;

	startTime = sqrl_get_real_time();
	retVal = escrypt_kdf( &local, (uint8_t*)password, password_len, salt, salt_len, N, ENSCRYPT_R, ENSCRYPT_P, t[1], 32 );
	if( retVal != 0 ) {
		goto DONE;
	}
	memcpy( buf, t[1], 32 );
	while( elapsed < millis ) {
		/*
		if( cb_ptr ) {
			if( lp != (p = (int)(elapsed / millis * 100)) ) {
				if( 0 == (*cb_ptr)(p, cb_data) ) {
					retVal = -1;
					break;
				}
				lp = p;
			}
		}
		*/
		if( 0 != (((int)i) & 1) ) {
			retVal = escrypt_kdf( &local, (uint8_t*)password, password_len, t[1], 32, N, ENSCRYPT_R, ENSCRYPT_P, t[0], 32 );
			((uint64_t*)buf)[0] ^= ((uint64_t*)t[0])[0];
			((uint64_t*)buf)[1] ^= ((uint64_t*)t[0])[1];
			((uint64_t*)buf)[2] ^= ((uint64_t*)t[0])[2];
			((uint64_t*)buf)[3] ^= ((uint64_t*)t[0])[3];
		} else {
			retVal = escrypt_kdf( &local, (uint8_t*)password, password_len, t[0], 32, N, ENSCRYPT_R, ENSCRYPT_P, t[1], 32 );
			((uint64_t*)buf)[0] ^= ((uint64_t*)t[1])[0];
			((uint64_t*)buf)[1] ^= ((uint64_t*)t[1])[1];
			((uint64_t*)buf)[2] ^= ((uint64_t*)t[1])[2];
			((uint64_t*)buf)[3] ^= ((uint64_t*)t[1])[3];
		}
		if( retVal != 0 ) goto DONE;
		i++;
		elapsed = (sqrl_get_real_time() - startTime) * 1000;
	}

DONE:
	//if( cb_ptr ) (*cb_ptr)(100, cb_data);

	if( retVal != 0 ) {
		sqrl_memzero( buf, 32 );
	}
	if( escrypt_free_local( &local ) ) {
		return -1; /* LCOV_EXCL_LINE */
	}
	return retVal == 0 ? i : -1;
#endif
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


void SqrlCrypt::sign( const std::string *msg, const uint8_t sk[32], const uint8_t pk[32], uint8_t sig[64] ) {
#ifdef ARDUINO
	Ed25519::sign( sig, sk, pk, utstring_body( msg ), utstring_len( msg ) );
#else
	uint8_t secret[crypto_sign_SECRETKEYBYTES];
	sqrl_mlock( secret, crypto_sign_SECRETKEYBYTES );
	memcpy( secret, sk, 32 );
	memcpy( secret + 32, pk, 32 );
	crypto_sign_detached(
		sig, NULL,
		(const unsigned char*)msg->data(), msg->length(),
		secret );
	sqrl_munlock( secret, crypto_sign_SECRETKEYBYTES );
#endif
}


bool SqrlCrypt::verifySignature( const std::string *msg, const uint8_t *sig, const uint8_t *pub ) {
#ifdef ARDUINO
	return Ed25519::verify( sig, pub, utstring_body( msg ), utstring_len( msg ) );
#else
	if( crypto_sign_verify_detached( sig, (const unsigned char *)msg->data(), msg->length(), pub ) == 0 ) {
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

