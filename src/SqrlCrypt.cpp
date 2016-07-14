#include "sqrl_internal.h"

#include "SqrlCrypt.h"
#include "aes.h"
#include "gcm.h"


#define ENSCRYPT_R 256
#define ENSCRYPT_P 1
#define SODIUM_SCRYPT crypto_pwhash_scryptsalsa208sha256_ll


int SqrlCrypt::enHash( uint64_t *out, const uint64_t *in ) {
	uint64_t trans[4];
	uint64_t tmp[4];
	sodium_mlock( trans, 32 );
	sodium_mlock( tmp, 32 );
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
	sodium_munlock( trans, 32 );
	sodium_munlock( tmp, 32 );
	return 0;
}

int SqrlCrypt::encrypt( uint8_t *cipherText, const uint8_t *plainText, size_t textLength,
	const uint8_t *key, const uint8_t *iv, const uint8_t *add, size_t add_len, uint8_t *tag ) {
	gcm_context ctx;
	size_t iv_len = 0;
	size_t tag_len = 0;
	int retVal;

	if( iv ) iv_len = 12;
	if( tag ) tag_len = 16;
	if( !add ) add_len = 0;

	gcm_setkey( &ctx, (unsigned char*)key, 32 );
	retVal = gcm_crypt_and_tag(
		&ctx, ENCRYPT,
		iv, iv_len,
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

int SqrlCrypt::enScrypt( SqrlTransaction *transaction,
	uint8_t *buf, const char *password, size_t password_len,
	const uint8_t *salt, uint8_t salt_len,
	uint16_t iterations, uint8_t nFactor ) {
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
		sodium_memzero( buf, 32 );
	}
	if( escrypt_free_local( &local ) ) {
		return -1; /* LCOV_EXCL_LINE */
	}
	return retVal == 0 ? (int)endTime : -1;
}

int SqrlCrypt::enScryptMillis( SqrlTransaction *transaction,
	uint8_t *buf, const char *password, size_t password_len,
	const uint8_t *salt, uint8_t salt_len,
	int millis, uint8_t nFactor ) {
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
		sodium_memzero( buf, 32 );
	}
	if( escrypt_free_local( &local ) ) {
		return -1; /* LCOV_EXCL_LINE */
	}
	return retVal == 0 ? i : -1;

}

void SqrlCrypt::generateIdentityLockKey( uint8_t ilk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] ) {
	uint8_t tmp[SQRL_KEY_SIZE];
	sodium_mlock( tmp, SQRL_KEY_SIZE );
	memcpy( tmp, iuk, SQRL_KEY_SIZE );
	SqrlCrypt::generateCurvePrivateKey( tmp );
	SqrlCrypt::generateCurvePublicKey( ilk, tmp );
	sodium_munlock( tmp, SQRL_KEY_SIZE );
}

void SqrlCrypt::generateLocalKey( uint8_t local[SQRL_KEY_SIZE], const uint8_t mk[SQRL_KEY_SIZE] ) {
	SqrlCrypt::enHash( (uint64_t*)local, (uint64_t*)mk );
}

void SqrlCrypt::generateMasterKey( uint8_t mk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] ) {
	SqrlCrypt::enHash( (uint64_t*)mk, (uint64_t*)iuk );
}

void SqrlCrypt::generateRandomLockKey( uint8_t rlk[SQRL_KEY_SIZE] ) {
	sqrl_entropy_bytes( rlk, SQRL_KEY_SIZE );
	SqrlCrypt::generateCurvePrivateKey( rlk );
}

void SqrlCrypt::generateServerUnlockKey( uint8_t suk[SQRL_KEY_SIZE], const uint8_t rlk[SQRL_KEY_SIZE] ) {
	SqrlCrypt::generateCurvePublicKey( suk, rlk );
}

void SqrlCrypt::generateVerifyUnlockKey( uint8_t vuk[SQRL_KEY_SIZE], const uint8_t ilk[SQRL_KEY_SIZE], const uint8_t rlk[SQRL_KEY_SIZE] ) {
	uint8_t tmp[SQRL_KEY_SIZE];
	sodium_mlock( tmp, SQRL_KEY_SIZE );
	SqrlCrypt::generateSharedSecret( tmp, ilk, rlk );
	SqrlCrypt::generatePublicKey( vuk, tmp );
	sodium_munlock( tmp, SQRL_KEY_SIZE );
}

void SqrlCrypt::generateUnlockRequestSigningKey( uint8_t ursk[SQRL_KEY_SIZE], const uint8_t suk[SQRL_KEY_SIZE], const uint8_t iuk[SQRL_KEY_SIZE] ) {
	uint8_t tmp[SQRL_KEY_SIZE];
	sodium_mlock( tmp, SQRL_KEY_SIZE );
	memcpy( tmp, iuk, SQRL_KEY_SIZE );
	SqrlCrypt::generateCurvePrivateKey( tmp );
	SqrlCrypt::generateSharedSecret( ursk, suk, tmp );
	sodium_munlock( tmp, SQRL_KEY_SIZE );
}


void SqrlCrypt::generatePublicKey( uint8_t *puk, const uint8_t *prk ) {
	uint8_t sk[crypto_sign_SECRETKEYBYTES];
	sodium_mlock( sk, crypto_sign_SECRETKEYBYTES );
	crypto_sign_seed_keypair( puk, sk, prk );
	sodium_munlock( sk, crypto_sign_SECRETKEYBYTES );
	//	ed25519_publickey( prk, puk );
}


void SqrlCrypt::sign( const UT_string *msg, const uint8_t sk[32], const uint8_t pk[32], uint8_t sig[64] ) {
	uint8_t secret[crypto_sign_SECRETKEYBYTES];
	sodium_mlock( secret, crypto_sign_SECRETKEYBYTES );
	memcpy( secret, sk, 32 );
	memcpy( secret + 32, pk, 32 );
	crypto_sign_detached(
		sig, NULL,
		(unsigned char*)utstring_body( msg ), utstring_len( msg ),
		secret );
	sodium_munlock( secret, crypto_sign_SECRETKEYBYTES );
	//	ed25519_sign(
	//		(unsigned char*)utstring_body(msg), 
	//		utstring_len(msg), 
	//		sk, pk, sig );

}


bool SqrlCrypt::verifySignature( const UT_string *msg, const uint8_t *sig, const uint8_t *pub ) {
	if( crypto_sign_verify_detached( sig, (unsigned char *)(utstring_body( msg )), utstring_len( msg ), pub ) == 0 ) {
		return true;
	}
	//	if( ed25519_sign_open( 
	//		(unsigned char *)utstring_body( msg ),
	//		utstring_len( msg ), pub, sig) == 0 ) {
	//		return true;
	//	}
	return false;
}


void SqrlCrypt::generateCurvePrivateKey( uint8_t *key ) {
	//	key[0]  &= 248;
	//	key[31] &= 127;
	//	key[31] |=  64;
	unsigned char tmp[32];
	sodium_mlock( tmp, SQRL_KEY_SIZE );
	crypto_sign_ed25519_sk_to_curve25519( tmp, key );
	memcpy( key, tmp, 32 );
	sodium_munlock( tmp, SQRL_KEY_SIZE );
}


void SqrlCrypt::generateCurvePublicKey( uint8_t *puk, const uint8_t *prk ) {
	crypto_scalarmult_base( puk, prk );
}



int SqrlCrypt::generateSharedSecret( uint8_t *shared, const uint8_t *puk, const uint8_t *prk ) {
	return crypto_scalarmult( shared, prk, puk );
}

