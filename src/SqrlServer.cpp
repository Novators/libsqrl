/** \file SqrlServer.cpp
 *
 * \author Adam Comley
 * 
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlServer.h"
#include "aes.h"
#include "SqrlUri.h"
#include "SqrlBase64.h"

SqrlServer::SqrlServer(
	const char *uri,
	const char *sfn,
	const char *passcode,
	size_t passcode_len )
{
	SqrlInit();
	memset( this, 0, sizeof( class SqrlServer ) );
	if( sfn ) {
		this->sfn = new SQRL_STRING( sfn );
	} else {
		SqrlUri *tmpUri = SqrlUri::parse( uri );
		if( tmpUri ) {
			char *tmp;
			tmp = tmpUri->getSiteKey();
			this->sfn = new SQRL_STRING( tmp );
			free( tmp );
			tmpUri->release();
		} else {
			this->sfn = new SQRL_STRING( "Invalid Server Configuration" );
		}
	}

	if( uri ) {
		const char *p, *pp;
		p = strstr( uri, SQRL_SERVER_TOKEN_SFN );
		if( p ) {
			SqrlBase64 b64 = SqrlBase64();
			pp = p + strlen( SQRL_SERVER_TOKEN_SFN );
			SQRL_STRING str = SQRL_STRING( uri, p - uri );
			b64.encode( &str, this->sfn, true );
			SQRL_STRING fullUri = str.append( pp );
			this->uri = SqrlUri::parse( fullUri.data() );
		} else {
			this->uri = SqrlUri::parse( uri );
		}
	}

	if( passcode ) {
		crypto_hash_sha256( this->key, (unsigned char*)passcode, passcode_len );
	} else {
		sqrl_randombytes( this->key, 32 );
	}

	this->nut_expires = SQRL_DEFAULT_NUT_LIFE * 1000000;
}

SqrlServer::~SqrlServer() {
	if( this->uri ) {
		this->uri = this->uri->release();
	}
	if( this->sfn ) delete(this->sfn);
	//if( this->user ) free( this->user );
	int i;
	for( i = 0; i < CONTEXT_KV_COUNT; i++ ) {
		if( this->context_strings[i] )
			free( this->context_strings[i] );
	}
	for( i = 0; i < CLIENT_KV_COUNT; i++ ) {
		if( this->client_strings[i] )
			free( this->client_strings[i] );
	}
	for( i = 0; i < SERVER_KV_COUNT; i++ ) {
		if( this->server_strings[i] )
			free( this->server_strings[i] );
	}
	if( this->reply ) free( this->reply );

	sqrl_memzero( this, sizeof( this ) );
}

bool SqrlServer::createNut( Sqrl_Nut *nut, uint32_t ip ) {
	if( !nut ) return false;
	Sqrl_Nut pt;
	pt.ip = ip;
	pt.timestamp = sqrl_get_timestamp();
	pt.random = sqrl_random();

	aes_context ctx;
	if( 0 != aes_setkey( &ctx, ENCRYPT, this->key, 16 ) ) {
		return false;
	}
	if( 0 != aes_cipher( &ctx, (unsigned char*)&pt, (unsigned char*)nut ) ) {
		sqrl_memzero( &ctx, sizeof( aes_context ) );
		return false;
	}
	sqrl_memzero( &ctx, sizeof( aes_context ) );
	return true;
}

bool SqrlServer::decryptNut( Sqrl_Nut *nut ) {
	if( !nut ) return false;
	Sqrl_Nut pt;
	memset( &pt, 0, sizeof( Sqrl_Nut ) );

	aes_context ctx;
	if( 0 != aes_setkey( &ctx, DECRYPT, this->key, 16 ) ) {
		return false;
	}
	if( 0 != aes_cipher( &ctx, (unsigned char*)nut, (unsigned char*)&pt ) ) {
		sqrl_memzero( &ctx, sizeof( aes_context ) );
		return false;
	}
	sqrl_memzero( &ctx, sizeof( aes_context ) );

	memcpy( nut, &pt, sizeof( Sqrl_Nut ) );
	return true;
}

void SqrlServer::addMAC( SQRL_STRING *str, char sep ) {
	if( !str ) return;
	uint8_t mac[crypto_auth_BYTES];

	crypto_auth( mac, (unsigned char *)str->data(), str->length(), this->key );
	if( sep > 0 ) {
		str->append( 1, sep );
		str->append( "mac=" );
	} else {
		str->append( "mac=" );
	}
	SQRL_STRING m = SQRL_STRING( (char*)mac, SQRL_SERVER_MAC_LENGTH );
	SqrlBase64().encode( str, &m, true );
}

bool SqrlServer::verifyMAC( SQRL_STRING *str ) {
	if( !str ) return false;
	size_t len = 0;
	const char *cstr = str->data();

	const char *m = strstr( cstr, "&mac=" );
	if( m ) {
		len = m - cstr;
		m += 5;
	} else {
		m = strstr( cstr, "mac=" );
		if( m ) {
			len = m - cstr;
			m += 4;
		}
	}
	if( m ) {
		uint8_t mac[crypto_auth_BYTES];
		crypto_auth( mac, (unsigned char *)cstr, len, this->key );
		SQRL_STRING *v = SqrlBase64().decode( NULL, &(SQRL_STRING( m )) );
		if( v ) {
			if( 0 == memcmp( mac, v->data(), SQRL_SERVER_MAC_LENGTH ) ) {
				delete v;
				return true;
			}
			delete v;
		}
	}
	return false;
}

SQRL_STRING *SqrlServer::createLink( uint32_t ip ) {
	SQRL_STRING *retVal = NULL;
	Sqrl_Nut nut;
	if( this->createNut( &nut, ip ) ) {
		char *challenge = this->uri->getChallenge();
		char *p, *pp;
		p = strstr( challenge, SQRL_SERVER_TOKEN_NUT );
		if( p ) {
			retVal = new SQRL_STRING( challenge, p - challenge );
			SqrlBase64().encode( retVal, &SQRL_STRING( (char*)(&nut), sizeof( Sqrl_Nut ) ), true );
			pp = p + strlen( SQRL_SERVER_TOKEN_NUT );
			retVal->append( pp );
			this->addMAC( retVal, '&' );
		}
		free( challenge );
	}
	return retVal;
}

