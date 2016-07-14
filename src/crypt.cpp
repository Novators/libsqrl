/** @file crypt.c Cryptographic primitives

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include <math.h>
#include "sqrl_internal.h"
#include "aes.h"
#include "gcm.h"
#include "SqrlCrypt.h"

uint32_t sqrl_crypt_enscrypt( Sqrl_Crypt_Context *sctx, uint8_t *key, const char *password, size_t password_len, enscrypt_progress_fn callback, void * callback_data ) 
{
	size_t salt_len = sctx->salt ? 16 : 0;
	uint32_t newCount;
	if( (sctx->flags & SQRL_MILLIS) == SQRL_MILLIS ) {
		newCount = SqrlCrypt::enScryptMillis( NULL, key, password, password_len, sctx->salt, (uint8_t)salt_len, sctx->count, sctx->nFactor );
		if( newCount == -1 ) return 0;
		sctx->count = newCount;
		sctx->flags &= ~SQRL_MILLIS;
		sctx->flags |= SQRL_ITERATIONS;
	} else {
		newCount = SqrlCrypt::enScrypt( NULL, key, password, password_len, sctx->salt, (uint8_t)salt_len, sctx->count, sctx->nFactor );
		if( newCount == -1 ) return 0;
	}
	return sctx->count;
}

bool sqrl_crypt_gcm( Sqrl_Crypt_Context *sctx, uint8_t *key ) 
{
	if( sctx->flags & SQRL_ENCRYPT ) {
		SqrlCrypt::encrypt( sctx->cipher_text, sctx->plain_text, sctx->text_len,
			key, sctx->iv, sctx->add, sctx->add_len, sctx->tag );
	} else {
		if( SqrlCrypt::decrypt( sctx->plain_text, sctx->cipher_text, sctx->text_len,
			key, sctx->iv, sctx->add, sctx->add_len, sctx->tag ) ) {
			return false;
		}
	}
	return true;
}

