/* client_protocol.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"

#define SITE_KEY_COUNT 5
#define SITE_KEY_LENGTH 3
#define SITE_KEY_VER 0
#define SITE_KEY_TIF 1
#define SITE_KEY_QRY 2
#define SITE_KEY_ASK 3
#define SITE_KEY_SUK 4

#define SITE_FLAG_TIF 1
#define SITE_FLAG_SFN 2
#define SITE_FLAG_VALID_REPLY 4
#define SITE_FLAG_VALID_CLIENT_STRING 8

#define FLAG_SET(f,v) f |= v
#define FLAG_CLEAR(f,v) f &= ~(v)
#define FLAG_CHECK(f,v) (v == (f & v))

static char key_strings[SITE_KEY_COUNT][SITE_KEY_LENGTH+1] = { 
	"ver", "tif", "qry", "ask", "suk"};

void sqrl_site_free( Sqrl_Client_Site *site )
{
	if( !site ) return;
	if( site->serverString ) {
		utstring_free( site->serverString );
		site->serverString = NULL;
	}
	if( site->clientString ) {
		utstring_free( site->clientString );
		site->clientString = NULL;
	}
	if( site->serverFriendlyName ) {
		free( site->serverFriendlyName );
		site->serverFriendlyName = NULL;
	}
}

bool sqrl_site_user_set( Sqrl_Client_Site *site )
{
	if( !site ) return false;
	bool retVal = true;
	UT_string *uid;
	UT_string *host;
	uint8_t tmp[SQRL_KEY_SIZE];
	uint8_t *mk, *piuk;

	utstring_new( uid );
	utstring_new( host );

	mk = sqrl_user_key( site->transaction, KEY_MK );
	if( !mk ) goto ERROR;

	if( !site->transaction->altIdentity ) {
		sqrl_client_call_select_alternate_identity( site->transaction );
	}

	// Create host string...
	if( site->transaction->altIdentity ) {
		utstring_printf( host, "%s+%s", site->transaction->uri->host, site->transaction->altIdentity );
	} else {
		utstring_printf( host, "%s", site->transaction->uri->host );
	}

	// Generate site private key
	if( ! site->key_sec ) site->key_sec = malloc( SQRL_KEY_SIZE );
	if( 0 != crypto_auth_hmacsha256( 
		site->key_sec,
		(unsigned char*)(utstring_body( host )),
		utstring_len( host ),
		mk )) {
		goto ERROR;
	}

	// Generate site public key
	if( ! site->key_pub ) site->key_pub = malloc( SQRL_KEY_SIZE );
	sqrl_ed_public_key( 
		site->key_pub,
		site->key_sec );

	// Do we have a previous key?
	piuk = sqrl_user_key( site->transaction, KEY_PIUK0 );
	if( piuk ) {
		// Regenerate old MK
		Sqrl_EnHash( 
			(uint64_t*)tmp, 
			(uint64_t*)piuk );
		if( ! site->key_psec ) site->key_psec = malloc( SQRL_KEY_SIZE );
		if( 0 != crypto_auth_hmacsha256( 
			site->key_psec,
			(unsigned char*)(utstring_body( host )),
			utstring_len( host ),
			tmp )) {
			goto ERROR;
		}
		if( !site->key_ppub ) site->key_ppub = malloc( SQRL_KEY_SIZE );
		sqrl_ed_public_key( 
			site->key_ppub,
			site->key_psec );
	}

	// Copy User Option Flags
	site->userOptFlags = sqrl_user_get_flags( site->transaction->user );

	goto DONE;

ERROR:
	printf( "ERROR\n" );
	retVal = false;


DONE:
	// Unlock and zero user credentials
	utstring_free( uid );
	utstring_free( host );
	sodium_memzero( tmp, SQRL_KEY_SIZE );
	return retVal;
}

void parseVer( struct Sqrl_Client_Site *site, char *str, size_t string_len )
{
	if( !site || !str || string_len == 0 ) return;
	long srv[SQRL_KNOWN_VERSIONS_COUNT + 1] = {0};
	static const long cli[SQRL_KNOWN_VERSIONS_COUNT + 1] = SQRL_CLIENT_VERSIONS;
	long a,b,n;
	char *start = str;
	char *end = str + string_len;
	char *sep;

	while( start < end ) {
		a = strtol( start, &sep, 10 );
		if( a < 0 ) a = 0;
		if( a <= SQRL_KNOWN_VERSIONS_COUNT ) {
			srv[a] = 1;
		}
		if( sep[0] == '-' ) {
			start = sep + 1;
			b = strtol( start, &sep, 10 );
			if( b < 0 ) b = 0;
			if( b < a ) b = a;
			if( b > SQRL_KNOWN_VERSIONS_COUNT ) b = SQRL_KNOWN_VERSIONS_COUNT;
			for( n = a+1; n <= b; n++ ) {
				//printf( "ver: %ld\n", n );
				srv[n] = 1;
			}
		}
		start = sep + 1;
	}

	site->version = 0;
	for( n = SQRL_KNOWN_VERSIONS_COUNT; n > 0; n-- ) {
		if( srv[n] == 1 && cli[n] == 1 ) {
			site->version = n;
			break;
		}
	}
}

void parseQry( struct Sqrl_Client_Site *site, const char *url, size_t url_len )
{
	if( !site || !url || url_len == 0 ) return;
	UT_string *chal;
	UT_string *srvStr;
	UT_string *newUrl;
	Sqrl_Uri *suri = site->transaction->uri;

	utstring_new( chal );
	utstring_new( srvStr );
	utstring_new( newUrl );

	utstring_printf( chal, "sqrl://%s", suri->host );
	utstring_printf( newUrl, "%s", suri->prefix );
	utstring_bincpy( chal, url, url_len );
	utstring_bincpy( newUrl, url, url_len );
	if( suri->challenge ) {
		free( suri->challenge );
	}
	if( suri->url ) {
		free( suri->url );
	}
	suri->challenge = calloc( utstring_len( chal ) + 1, 1 );
	suri->url = calloc( utstring_len( newUrl ) + 1, 1 );
	strcpy( suri->challenge, utstring_body( chal ));
	strcpy( suri->url, utstring_body( newUrl ));

	if( site->serverString ) {
		utstring_free( site->serverString );
	}
	sqrl_b64u_encode( srvStr, (uint8_t*)utstring_body( chal ), utstring_len( chal ));
	site->serverString = srvStr;

	utstring_free( chal );
}

void parseSuk( struct Sqrl_Client_Site *site, char *value, size_t value_len )
{
	if( !site || !value || value_len == 0 ) return;
	UT_string *s;
	utstring_new( s );

	sqrl_b64u_decode( s, value, value_len );
	if( utstring_len(s) != 32 ) {
		//printf( "Invalid Key: %s\n", value );
		utstring_free( s );
		return;
	}
	if( site->key_suk ) free( site->key_suk );
	site->key_suk = malloc( SQRL_KEY_SIZE );
	memcpy( site->key_suk, utstring_body(s), SQRL_KEY_SIZE );
	utstring_free( s );
}

int parseKeyValue( struct Sqrl_Client_Site *site, char *key, size_t key_len, char *value, size_t value_len )
{
	if( key_len != SITE_KEY_LENGTH ) return -1;
	int key_type = -1;
	int i;
	char theKey[SITE_KEY_LENGTH+1];
	char theValue[value_len + 1];
	memcpy( theKey, key, key_len );
	theKey[key_len] = 0;
	sqrl_lcstr( theKey );
	memcpy( theValue, value, value_len );
	theValue[value_len] = 0;

	for( i = 0; i < SITE_KEY_COUNT; i++ ) {
		if( strcmp( theKey, key_strings[i] ) == 0 ) {
			key_type = i;
			break;
		}
	}
	switch( key_type ) {
	case SITE_KEY_VER:
		parseVer( site, theValue, value_len );
		break;
	case SITE_KEY_TIF:
		site->tif = sqrl_hex2uint( theValue );
		FLAG_SET(site->flags, SITE_FLAG_TIF);
		break;
	case SITE_KEY_QRY:
		parseQry( site, theValue, value_len );
		break;
	case SITE_KEY_ASK:
		// TODO: Implement ASK
		break;
	case SITE_KEY_SUK:
		parseSuk( site, theValue, value_len );
		break;
	default:
		// Ignore unknown key
		break;
	}
	return key_type;
}

void sqrl_site_parse_result( Sqrl_Client_Site *site, const char *result, size_t result_len )
{
	if( !site || !result || result_len == 0 ) return;
	int found_keys = 0;
	int current_key = 0;
	uint16_t required_keys = 
		(1<<SITE_KEY_VER) |
		(1<<SITE_KEY_TIF) |
		(1<<SITE_KEY_QRY);

	char *end, *key, *value, *sep;
	size_t key_len, val_len;
	UT_string *rStr;

	FLAG_CLEAR(site->flags, SITE_FLAG_VALID_REPLY);

	utstring_new( rStr );
	sqrl_b64u_decode( rStr, result, result_len );

	key = utstring_body( rStr );
	end = key + utstring_len( rStr );

	while( key < end ) {
		value = strchr( key, '=' );
		sep = strstr( key, "\r\n" );
		if( !sep ) sep = end;
		if( value > sep ) value = NULL;
		if( value ) {
			key_len = value - key;
			value++; // Skip '='
			val_len = sep - value;
		} else {
			key_len = sep - key;
			val_len = 0;
		}
		current_key = parseKeyValue( site, key, key_len, value, val_len );
		if( current_key > -1 ) {
			found_keys |= (1<<current_key);
		}
		key = sep + 2;
	}

	// Should return entire server response with next query...
	utstring_clear( rStr );
	utstring_bincpy( rStr, result, result_len );

	if( site->serverString ) {
		utstring_free( site->serverString );
	}
	site->serverString = rStr;

	if( required_keys == (found_keys & required_keys) ) {
		FLAG_SET(site->flags, SITE_FLAG_VALID_REPLY);
	}

}

int sqrl_site_tif( Sqrl_Client_Site *site )
{
	if( !site ) return false;
	int retVal = site->tif;
	if( ! FLAG_CHECK(site->flags, SITE_FLAG_TIF) ) retVal = -1;
	return retVal;
}

bool sqrl_site_has_server_friendly_name( Sqrl_Client_Site *site )
{
	bool retVal = false;
	if( !site ) return false;
	if( FLAG_CHECK( site->flags, SITE_FLAG_SFN )) 
		retVal = true;
	return retVal;
}

UT_string *sqrl_site_server_friendly_name( Sqrl_Client_Site *site )
{
	if( !site ) return NULL;
	UT_string *ret = NULL;
	if( FLAG_CHECK( site->flags, SITE_FLAG_SFN )) {
		utstring_new( ret );
		utstring_bincpy( ret, site->serverFriendlyName, strlen(site->serverFriendlyName ));
	}
	return ret;
}

UT_string *sqrl_site_domain( Sqrl_Client_Site *site )
{
	if( !site ) return NULL;
	UT_string *ret = NULL;

	if( site->transaction->uri && site->transaction->uri->host ) {
		utstring_new( ret );
		utstring_bincpy( ret, site->transaction->uri->host, strlen( site->transaction->uri->host ));
	}

	return ret;
}

void sqrl_site_encode_client_string( Sqrl_Client_Site *site, UT_string *newStr ) 
{
	if( !site ) return;

	UT_string *cpy;
	utstring_new( cpy );
	if( newStr ) {
		sqrl_b64u_encode( cpy, (uint8_t*)utstring_body( newStr), utstring_len( newStr ));
	}

	if( site->clientString ) {
		utstring_free( site->clientString );
	}
	site->clientString = cpy;
}

void sqrl_site_add_key_value( UT_string *str, char *key, char *value )
{
	if( !str || !key ) return;
	char crlf[3] = "\r\n";
	if( utstring_len( str ) == 0 ) crlf[0] = 0;
	if( value ) {
		utstring_printf( str, "%s%s=%s", crlf, key, value );
	} else {
		utstring_printf( str, "%s%s=", crlf, key );
	}
}

void sqrl_site_generate_opts( struct Sqrl_Client_Site *site, UT_string *qry ) {
	if( !site || !qry ) return;
	uint16_t flags = ( site->userOptFlags & SQRL_OPTION_REQUEST_SQRL_ONLY ) |
					 ( site->userOptFlags & SQRL_OPTION_REQUEST_ID_LOCK );
	if( flags ) {
		switch( flags ) {
			case SQRL_OPTION_REQUEST_SQRL_ONLY:
				sqrl_site_add_key_value( qry, "opt", "sqrlonly" );
				break;
			case SQRL_OPTION_REQUEST_ID_LOCK:
				sqrl_site_add_key_value( qry, "opt", "hardlock" );
				break;
			default:
				sqrl_site_add_key_value( qry, "opt", "sqrlonly~hardlock" );
				break;
		}
	}
}

void sqrl_site_create_unlock_keys( struct Sqrl_Client_Site *site ) {
	if( !site ) return;
	uint8_t scratch[64];

	if( !site->key_suk ) site->key_suk = malloc( SQRL_KEY_SIZE );
	if( !site->key_vuk ) site->key_vuk = malloc( SQRL_KEY_SIZE );
	uint8_t *ilk = sqrl_user_key( site->transaction, KEY_ILK );
	sodium_mlock( scratch, 64 );
	sqrl_entropy_get( scratch, 1 );
	memcpy( scratch+32, scratch, 32 );
	sqrl_curve_private_key( scratch+32 );
	sqrl_curve_public_key( site->key_suk, scratch+32);
	sqrl_make_shared_secret( scratch, ilk, scratch+32 );
	sqrl_curve_private_key( scratch );
	sqrl_curve_public_key( site->key_vuk, scratch );

	sodium_munlock( scratch, 64 );
}

void sqrl_site_generate_keys( struct Sqrl_Client_Site *site, UT_string *clientString )
{
	if( !site || !clientString ) return;
	sqrl_site_add_key_value( clientString, "idk", NULL );
	sqrl_b64u_encode_append( clientString, site->key_pub, SQRL_KEY_SIZE );

	if( site->key_ppub ) {
		sqrl_site_add_key_value( clientString, "pidk", NULL );
		sqrl_b64u_encode_append( clientString, site->key_ppub, SQRL_KEY_SIZE );
	}

	if( site->currentTransaction == SQRL_TRANSACTION_AUTH_IDENT ) {
		if( (site->tif & SQRL_TIF_ID_MATCH) == 0 && 
			(site->tif & SQRL_TIF_PREVIOUS_ID_MATCH) == 0 ) {
			// Identity not registered; Generate keys...
			sqrl_site_create_unlock_keys( site );
			sqrl_site_add_key_value( clientString, "suk", NULL );
			sqrl_b64u_encode_append( clientString, site->key_suk, SQRL_KEY_SIZE );
			sqrl_site_add_key_value( clientString, "vuk", NULL );
			sqrl_b64u_encode_append( clientString, site->key_vuk, SQRL_KEY_SIZE );
		}
	}
	if( (site->currentTransaction == SQRL_TRANSACTION_AUTH_ENABLE ||
			((site->currentTransaction == SQRL_TRANSACTION_AUTH_IDENT) &&
			 (site->tif & SQRL_TIF_PREVIOUS_ID_MATCH)))) {
		if( site->key_ursk ) {
			free( site->key_ursk );
			site->key_ursk = NULL;
		}
		if( site->key_urpk ) {
			free( site->key_urpk );
			site->key_urpk = NULL;
		}
		if( site->currentTransaction == SQRL_TRANSACTION_AUTH_IDENT ) {
			uint8_t *piuk = sqrl_user_key( site->transaction, KEY_PIUK0 );
			if( piuk ) {
				if( !site->key_ursk ) site->key_ursk = malloc( SQRL_KEY_SIZE );
				sqrl_make_shared_secret( 
					site->key_ursk,
					site->key_suk,
					piuk );
			}
		} else {
			uint8_t *iuk = sqrl_user_key( site->transaction, KEY_IUK );
			if( iuk ) {
				if( !site->key_ursk ) site->key_ursk = malloc( SQRL_KEY_SIZE );
				sqrl_make_shared_secret( 
					site->key_ursk,
					site->key_suk,
					iuk );
			}
		}
		if( site->key_ursk ) {
			if( ! site->key_urpk ) site->key_urpk = malloc( SQRL_KEY_SIZE );
			sqrl_ed_public_key( 
				site->key_urpk,
				site->key_ursk );
		}
	}
}

/**
Creates the client's body text for sending to the SQRL server

@param site the \p Sqrl_Client_Site
@param cmd One of: \p SQRL_TRANSACTION_AUTH_QUERY SQRL_TRANSACTION_AUTH_IDENT SQRL_TRANSACTION_AUTH_DISABLE SQRL_TRANSACTION_AUTH_ENABLE
@return true on success, false on failure
*/
DLL_PUBLIC 
bool sqrl_site_generate_client_body( Sqrl_Client_Site *site )
{
	if( !site ) return false;
	bool success = true;
	UT_string *clientString;
	utstring_new( clientString );

	FLAG_SET( site->flags, SITE_FLAG_VALID_CLIENT_STRING );

	if( !clientString ) goto ERROR;

	// There MUST have been a previous valid response from server,
	// Except for the initial QUERY command.
	if( site->currentTransaction != SQRL_TRANSACTION_AUTH_QUERY && ! FLAG_CHECK( site->flags, SITE_FLAG_VALID_REPLY )) {
		goto ERROR;
	}

	sqrl_site_add_key_value( clientString, "ver", SQRL_VERSION_STRING );
	switch( site->currentTransaction ) {
	case SQRL_TRANSACTION_AUTH_QUERY:
		sqrl_site_add_key_value( clientString, "cmd", "query" );
		break;
	case SQRL_TRANSACTION_AUTH_IDENT:
		sqrl_site_add_key_value( clientString, "cmd", "ident" );
		break;
	case SQRL_TRANSACTION_AUTH_DISABLE:
		if( site->tif & SQRL_TIF_SQRL_DISABLED ) goto ERROR;
		sqrl_site_add_key_value( clientString, "cmd", "disable" );
		break;
	case SQRL_TRANSACTION_AUTH_ENABLE:
		if( (site->tif & SQRL_TIF_SQRL_DISABLED) == 0 ) goto ERROR;
		sqrl_site_add_key_value( clientString, "cmd", "enable" );
		break;
	case SQRL_TRANSACTION_AUTH_REMOVE:
		if( (site->tif & SQRL_TIF_SQRL_DISABLED) == 0 ) goto ERROR;
		sqrl_site_add_key_value( clientString, "cmd", "remove" );
		break;
	default:
		printf( "Unknown SQRL command!\n" );
		goto ERROR;
	}
	sqrl_site_generate_opts( site, clientString );
	sqrl_site_generate_keys( site, clientString );
	utstring_bincpy( clientString, "\r\n", 2 );
	printf( "client=\n%s", utstring_body( clientString ));
	goto DONE;

ERROR:
	FLAG_CLEAR( site->flags, SITE_FLAG_VALID_CLIENT_STRING );
	success = false;

DONE:
	if( ! FLAG_CHECK( site->flags, SITE_FLAG_VALID_CLIENT_STRING )) {
		success = false;
	}
	if( success ) {
		sqrl_site_encode_client_string( site, clientString );
	}
	if( clientString ) utstring_free( clientString );
	return success;
}

/**
Gets the client body text to send to the SQRL server.  Call this only after a
successful \p sqrl_site_generate_client_body()

\warning Allocates a new UT_string object!  Be sure to call utstring_free() when done!

@param site the \p Sqrl_Client_Site
@return pointer to a new UT_string object containing the client's body text
*/
DLL_PUBLIC 
UT_string *sqrl_site_client_body( Sqrl_Client_Site *site ) 
{
	if( !site ) return NULL;
	UT_string *result, *buffer;
	uint8_t binSig[64];

	if( ! FLAG_CHECK( site->flags, SITE_FLAG_VALID_CLIENT_STRING )) {
		return NULL;
	}

	utstring_new( result );
	utstring_new( buffer );

	if( site->clientString ) {
		utstring_bincpy( result, "client=", 7 );
		utstring_concat( result, site->clientString );
		utstring_concat( buffer, site->clientString );
	}
	if( site->serverString ) {
		utstring_bincpy( result, "&server=", 8 );
		utstring_concat( result, site->serverString );
		utstring_concat( buffer, site->serverString );
	}
	utstring_bincpy( result, "&ids=", 5 );
	sqrl_sign( buffer, site->key_sec, site->key_pub, binSig );
	sqrl_b64u_encode_append( result, binSig, SQRL_SIG_SIZE );
	if( site->key_psec ) {
		utstring_bincpy( result, "&pids=", 6 );
		sqrl_sign( buffer, site->key_psec, site->key_ppub, binSig );
		sqrl_b64u_encode_append( result, binSig, SQRL_SIG_SIZE );
	}
	if( site->key_ursk ) {
		utstring_bincpy( result, "&urs=", 5 );
		sqrl_sign( buffer, site->key_ursk, site->key_urpk, binSig );
		sqrl_b64u_encode_append( result, binSig, SQRL_SIG_SIZE );
	}

	utstring_free( buffer );
	return result;
}

void sqrl_client_create_site( Sqrl_Client_Site *site, Sqrl_Client_Transaction *transaction )
{
	memset( site, 0, sizeof( Sqrl_Client_Site ));
	site->transaction = transaction;
	site->currentTransaction = SQRL_TRANSACTION_AUTH_QUERY;

	if( site->serverString ) {
		utstring_free( site->serverString );
	}
	UT_string *srvStr;
	utstring_new( srvStr );
	printf( "server=\n%s\n", site->transaction->uri->challenge );
	sqrl_b64u_encode( srvStr, (uint8_t*)site->transaction->uri->challenge, strlen( site->transaction->uri->challenge ));
	site->serverString = srvStr;

	sqrl_site_user_set( site );
}

Sqrl_Transaction_Status sqrl_client_do_ident( Sqrl_Client_Transaction *transaction )
{
	Sqrl_Client_Site site;
	sqrl_client_create_site( &site, transaction );
	if( sqrl_site_generate_client_body( &site )) {
		UT_string *bdy;
		bdy = sqrl_site_client_body( &site );
		sqrl_client_call_send(
			transaction, transaction->uri->url, strlen( transaction->uri->url ),
			utstring_body( bdy ), utstring_len( bdy ));
		utstring_free( bdy );
	}
	return SQRL_TRANSACTION_STATUS_FAILED;
}

