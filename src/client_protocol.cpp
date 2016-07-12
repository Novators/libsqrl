/* client_protocol.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "sqrl.h"
#include "SqrlUri.h"
#include "SqrlUser.h"
#include "SqrlTransaction.h"

#define SITE_KV_COUNT 6
#define SITE_KV_LENGTH 3
#define SITE_KV_VER 0
#define SITE_KV_TIF 1
#define SITE_KV_QRY 2
#define SITE_KV_ASK 3
#define SITE_KV_SUK 4
#define SITE_KV_NUT 5

#define SITE_FLAG_TIF 1
#define SITE_FLAG_SFN 2
#define SITE_FLAG_VALID_SERVER_STRING 4
#define SITE_FLAG_VALID_CLIENT_STRING 8

static char kv_strings[SITE_KV_COUNT][SITE_KV_LENGTH+1] = { 
	"ver", "tif", "qry", "ask", "suk", "nut"};

static int previousKeys[] = {KEY_PIUK0, KEY_PIUK1, KEY_PIUK2, KEY_PIUK3};
static uint8_t emptyKey[SQRL_KEY_SIZE] = {0};

bool sqrl_site_set_user_keys( Sqrl_Site *site )
{
	if( !site ) return false;
	bool retVal = true;
	UT_string *uid;
	UT_string *host;
	uint8_t *mk, *piuk;
	uint8_t tmp[SQRL_KEY_SIZE];

	utstring_new( uid );
	utstring_new( host );

	mk = site->transaction->getUser()->key( site->transaction, KEY_MK );
	if( !mk ) goto ERR;

	if( !site->transaction->getAltIdentity() ) {
		sqrl_client_call_select_alternate_identity( site->transaction );
	}

	// Create host string...
	char *str = site->transaction->getUri()->getHost();
	char *alt = site->transaction->getAltIdentity();
	if( alt ) {
		utstring_printf( host, "%s+%s", str, alt );
	} else {
		utstring_printf( host, "%s", str );
	}
	free(str);

	// Generate site private key
	if( 0 != crypto_auth_hmacsha256( 
		site->keys[SITE_KEY_SEC],
		(unsigned char*)(utstring_body( host )),
		utstring_len( host ),
		mk )) {
		goto ERR;
	}
	site->keys[SITE_KEY_LOOKUP][SITE_KEY_SEC] = 1;

	// Generate site public key
	sqrl_ed_public_key( 
		site->keys[SITE_KEY_PUB],
		site->keys[SITE_KEY_SEC] );
	site->keys[SITE_KEY_LOOKUP][SITE_KEY_PUB] = 1;

	// Copy User Option Flags
	site->userOptFlags = site->transaction->getUser()->getFlags();

	// Generate previous keys
	piuk = site->transaction->getUser()->key( site->transaction, previousKeys[ site->previous_identity ]);
	while( piuk && (0 == sodium_memcmp( piuk, emptyKey, SQRL_KEY_SIZE ))) {
		site->previous_identity++;
		if( site->previous_identity > 3 ) {
			site->previous_identity = 3;
			piuk = NULL;
			break;
		}
		piuk = site->transaction->getUser()->key( site->transaction, previousKeys[ site->previous_identity ]);
	}

	if( piuk ) {
		// Regenerate old MK
		Sqrl_EnHash( 
			(uint64_t*)tmp, 
			(uint64_t*)piuk );
		if( 0 != crypto_auth_hmacsha256( 
			site->keys[SITE_KEY_PSEC],
			(unsigned char*)(utstring_body( host )),
			utstring_len( host ),
			tmp )) {
			goto ERR;
		}
		site->keys[SITE_KEY_LOOKUP][SITE_KEY_PSEC] = 1;
		sqrl_ed_public_key( 
			site->keys[SITE_KEY_PPUB],
			site->keys[SITE_KEY_PSEC] );
		site->keys[SITE_KEY_LOOKUP][SITE_KEY_PPUB] = 1;
	}


	goto DONE;

ERR:
	retVal = false;


DONE:
	// Unlock and zero user credentials
	sodium_memzero( tmp, SQRL_KEY_SIZE );
	utstring_free( uid );
	utstring_free( host );
	return retVal;
}

void parseVer( struct Sqrl_Site *site, char *str, size_t string_len )
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

void parseQry( struct Sqrl_Site *site, const char *url, size_t url_len )
{
	if( !site || !url || url_len == 0 ) return;
	UT_string *chal;
	UT_string *srvStr;
	UT_string *newUrl;
	SqrlTransaction *transaction = site->transaction;
	SqrlUri *suri = transaction->getUri();
	char *str;

	utstring_new( chal );
	utstring_new( srvStr );
	utstring_new( newUrl );

	str = suri->getHost();
	utstring_printf( chal, "sqrl://%s", str );
	free(str);
	str = suri->getPrefix();
	utstring_printf( newUrl, "%s", str );
	free(str);
	utstring_bincpy( chal, url, url_len );
	utstring_bincpy( newUrl, url, url_len );
	suri->setChallenge(utstring_body(chal));
	suri->setUrl(utstring_body(newUrl));

	if( site->serverString ) {
		utstring_free( site->serverString );
	}
	sqrl_b64u_encode( srvStr, (uint8_t*)utstring_body( chal ), utstring_len( chal ));
	site->serverString = srvStr;

	utstring_free( chal );
}

void parseSuk( struct Sqrl_Site *site, char *value, size_t value_len )
{
	if( !site || !value || value_len == 0 ) return;
	site->keys[SITE_KEY_LOOKUP][SITE_KEY_SUK] = 0;
	UT_string *s;
	utstring_new( s );

	sqrl_b64u_decode( s, value, value_len );
	if( utstring_len(s) != 32 ) {
		utstring_free( s );
		return;
	}
	memcpy( site->keys[SITE_KEY_SUK], utstring_body(s), SQRL_KEY_SIZE );
	site->keys[SITE_KEY_LOOKUP][SITE_KEY_SUK] = 1;
	utstring_free( s );
}

int parseKeyValue( struct Sqrl_Site *site, char *key, size_t key_len, char *value, size_t value_len )
{
	if( key_len != SITE_KV_LENGTH ) return -1;
	int key_type = -1;
	int i;
	char theKey[SITE_KV_LENGTH+1];
	char *theValue = (char*)malloc(value_len + 1);
	memcpy( theKey, key, key_len );
	memcpy( theValue, value, value_len );
	theKey[key_len] = 0;
	theValue[value_len] = 0;
	sqrl_lcstr( theKey );

	for( i = 0; i < SITE_KV_COUNT; i++ ) {
		if( strcmp( theKey, kv_strings[i] ) == 0 ) {
			key_type = i;
			break;
		}
	}
	switch( key_type ) {
	case SITE_KV_VER:
		parseVer( site, theValue, value_len );
		break;
	case SITE_KV_TIF:
		site->tif = sqrl_hex2uint( theValue );
		FLAG_SET(site->flags, SITE_FLAG_TIF);
		break;
	case SITE_KV_QRY:
		parseQry( site, theValue, value_len );
		break;
	case SITE_KV_ASK:
		// TODO: Implement ASK
		break;
	case SITE_KV_SUK:
		parseSuk( site, theValue, value_len );
		break;
	default:
		break;
	}
	free(theValue);
	return key_type;
}

void sqrl_site_parse_result( Sqrl_Site *site, const char *result, size_t result_len )
{
	if( !site || !result || result_len == 0 ) return;
	int found_keys = 0;
	int current_key = 0;
	uint16_t required_keys = 
		(1<<SITE_KV_VER) |
		(1<<SITE_KV_TIF) |
		(1<<SITE_KV_QRY) |
		(1<<SITE_KV_NUT);

	char *str, *key, *val;
	size_t key_len, val_len;
	UT_string *rStr;

	FLAG_CLEAR(site->flags, SITE_FLAG_VALID_SERVER_STRING);
	utstring_new( rStr );
	utstring_bincpy( rStr, result, result_len );

	str = utstring_body( rStr );

    while( sqrl_parse_key_value( &str, &key, &val, &key_len, &val_len, "\r\n" )) {
    	current_key = parseKeyValue( site, key, key_len, val, val_len );
		if( current_key > -1 ) {
			found_keys |= (1<<current_key);
		}
	}

	// Should return entire server response with next query...
	utstring_clear( rStr );
	sqrl_b64u_encode( rStr, (uint8_t*)result, result_len );
	//utstring_bincpy( rStr, result, result_len );

	if( site->serverString ) {
		utstring_free( site->serverString );
	}
	site->serverString = rStr;

	if( required_keys == (found_keys & required_keys) ) {
		FLAG_SET(site->flags, SITE_FLAG_VALID_SERVER_STRING);
	}

}

int sqrl_site_tif( Sqrl_Site *site )
{
	if( !site ) return false;
	int retVal = site->tif;
	if( ! FLAG_CHECK(site->flags, SITE_FLAG_TIF) ) retVal = -1;
	return retVal;
}

bool sqrl_site_has_server_friendly_name( Sqrl_Site *site )
{
	bool retVal = false;
	if( !site ) return false;
	if( FLAG_CHECK( site->flags, SITE_FLAG_SFN )) 
		retVal = true;
	return retVal;
}

UT_string *sqrl_site_server_friendly_name( Sqrl_Site *site )
{
	if( !site ) return NULL;
	UT_string *ret = NULL;
	if( FLAG_CHECK( site->flags, SITE_FLAG_SFN )) {
		utstring_new( ret );
		utstring_bincpy( ret, site->serverFriendlyName, strlen(site->serverFriendlyName ));
	}
	return ret;
}

UT_string *sqrl_site_domain( Sqrl_Site *site )
{
	if( !site ) return NULL;
	UT_string *ret = NULL;
	char *tmpString;

	SqrlUri *uri = site->transaction->getUri();
	if( uri && uri->getHostLength() ) {
		utstring_new( ret );
		tmpString = uri->getHost();
		utstring_bincpy( ret, tmpString, strlen(tmpString));
		free(tmpString);
	}

	return ret;
}

void sqrl_site_encode_client_string( Sqrl_Site *site, UT_string *newStr ) 
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

void sqrl_site_generate_opts( struct Sqrl_Site *site, UT_string *qry ) {
	if( !site || !qry ) return;
	char sep = 0;
	UT_string *val;
	utstring_new( val );
	if( site->userOptFlags & SQRL_OPTION_REQUEST_SQRL_ONLY ) {
		utstring_printf( val, "%s", SQRL_OPTION_TOKEN_SQRLONLY );
		sep = SQRL_OPTION_TOKEN_SEPARATOR;
	}
	if( site->userOptFlags & SQRL_OPTION_REQUEST_ID_LOCK ) {
		if( sep ) {
			utstring_printf( val, "%c%s", sep, SQRL_OPTION_TOKEN_HARDLOCK );
		} else {
			utstring_printf( val, "%s", SQRL_OPTION_TOKEN_HARDLOCK );
		}
	}
	if( utstring_len( val ) > 0 ) {
		sqrl_site_add_key_value( qry, "opt", utstring_body( val ));
	}
	utstring_free( val );
	// TODO: Handle CPS and SUK options
}

void sqrl_site_create_unlock_keys( struct Sqrl_Site *site ) {
	if( !site ) return;
	uint8_t scratch[64];

	uint8_t *ilk = site->transaction->getUser()->key( site->transaction, KEY_ILK );
	sodium_mlock( scratch, 64 );
	uint8_t rlk[SQRL_KEY_SIZE];
	sqrl_gen_rlk( rlk );
	sqrl_curve_private_key( rlk );
	sqrl_gen_suk( site->keys[SITE_KEY_SUK], rlk );
	sqrl_gen_vuk( site->keys[SITE_KEY_VUK], ilk, rlk );

	site->keys[SITE_KEY_LOOKUP][SITE_KEY_SUK] = 1;
	site->keys[SITE_KEY_LOOKUP][SITE_KEY_VUK] = 1;
	sodium_munlock( scratch, 64 );
}

void sqrl_site_generate_keys( struct Sqrl_Site *site, UT_string *clientString )
{
	if( !site || !clientString ) return;
	sqrl_site_add_key_value( clientString, "idk", NULL );
	sqrl_b64u_encode_append( clientString, site->keys[SITE_KEY_PUB], SQRL_KEY_SIZE );

	if( site->keys[SITE_KEY_LOOKUP][SITE_KEY_PPUB] ) {
		sqrl_site_add_key_value( clientString, "pidk", NULL );
		sqrl_b64u_encode_append( clientString, site->keys[SITE_KEY_PPUB], SQRL_KEY_SIZE );
	}

	if( site->currentTransaction == SQRL_TRANSACTION_AUTH_IDENT ) {
		if( (site->tif & SQRL_TIF_ID_MATCH) == 0 && 
			(site->tif & SQRL_TIF_PREVIOUS_ID_MATCH) == 0 ) {
			// Identity not registered; Generate keys...
			sqrl_site_create_unlock_keys( site );
			sqrl_site_add_key_value( clientString, "suk", NULL );
			sqrl_b64u_encode_append( clientString, site->keys[SITE_KEY_SUK], SQRL_KEY_SIZE );
			sqrl_site_add_key_value( clientString, "vuk", NULL );
			sqrl_b64u_encode_append( clientString, site->keys[SITE_KEY_VUK], SQRL_KEY_SIZE );
		}
	}
	if( (site->currentTransaction == SQRL_TRANSACTION_AUTH_ENABLE ) ||
		(site->currentTransaction == SQRL_TRANSACTION_AUTH_REMOVE ) ||
		((site->currentTransaction == SQRL_TRANSACTION_AUTH_IDENT) &&
			(site->tif & SQRL_TIF_PREVIOUS_ID_MATCH))) {
		site->keys[SITE_KEY_LOOKUP][SITE_KEY_URSK] = 0;
		site->keys[SITE_KEY_LOOKUP][SITE_KEY_URPK] = 0;
		uint8_t *tiuk = NULL;
		if( FLAG_CHECK( site->tif, SQRL_TIF_PREVIOUS_ID_MATCH )) {
			tiuk = site->transaction->getUser()->key( site->transaction, KEY_PIUK0 + site->previous_identity );
		} else if( FLAG_CHECK( site->tif, SQRL_TIF_ID_MATCH )) {
			tiuk = site->transaction->getUser()->key( site->transaction, KEY_IUK );
		}
		if( tiuk ) {
			site->keys[SITE_KEY_LOOKUP][SITE_KEY_URSK] = 1;
			sqrl_gen_ursk( site->keys[SITE_KEY_URSK],
				site->keys[SITE_KEY_SUK],
				tiuk );

			site->keys[SITE_KEY_LOOKUP][SITE_KEY_URPK] = 1;
			sqrl_ed_public_key( 
				site->keys[SITE_KEY_URPK],
				site->keys[SITE_KEY_URSK] );
			if( site->currentTransaction == SQRL_TRANSACTION_AUTH_IDENT ) {
				sqrl_site_create_unlock_keys( site );
				sqrl_site_add_key_value( clientString, "suk", NULL );
				sqrl_b64u_encode_append( clientString, site->keys[SITE_KEY_SUK], SQRL_KEY_SIZE );
				sqrl_site_add_key_value( clientString, "vuk", NULL );
				sqrl_b64u_encode_append( clientString, site->keys[SITE_KEY_VUK], SQRL_KEY_SIZE );
			}
		}
	}
}

/**
Creates the client's body text for sending to the SQRL server

@param site the \p Sqrl_Site
@param cmd One of: \p SQRL_TRANSACTION_AUTH_QUERY SQRL_TRANSACTION_AUTH_IDENT SQRL_TRANSACTION_AUTH_DISABLE SQRL_TRANSACTION_AUTH_ENABLE
@return true on success, false on failure
*/
 
bool sqrl_site_generate_client_body( Sqrl_Site *site )
{
	if( !site ) return false;
	UT_string *clientString = NULL;
	bool success = sqrl_site_set_user_keys( site );
	if( !success ) goto ERR;
	utstring_new( clientString );

	FLAG_SET( site->flags, SITE_FLAG_VALID_CLIENT_STRING );

	if( !clientString ) goto ERR;

	// There MUST have been a previous valid response from server,
	// Except for the initial QUERY command.
	if( site->currentTransaction != SQRL_TRANSACTION_AUTH_QUERY && ! FLAG_CHECK( site->flags, SITE_FLAG_VALID_SERVER_STRING )) {
		goto ERR;
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
		if( site->tif & SQRL_TIF_SQRL_DISABLED ) goto ERR;
		sqrl_site_add_key_value( clientString, "cmd", "disable" );
		break;
	case SQRL_TRANSACTION_AUTH_ENABLE:
		if( (site->tif & SQRL_TIF_SQRL_DISABLED) == 0 ) goto ERR;
		sqrl_site_add_key_value( clientString, "cmd", "enable" );
		break;
	case SQRL_TRANSACTION_AUTH_REMOVE:
		if( (site->tif & SQRL_TIF_SQRL_DISABLED) == 0 ) goto ERR;
		sqrl_site_add_key_value( clientString, "cmd", "remove" );
		break;
	default:
#if DEBUG_PRINT_CLIENT_PROTOCOL
		printf( "Unknown SQRL command!\n" );
#endif
		goto ERR;
	}
	sqrl_site_generate_opts( site, clientString );
	sqrl_site_generate_keys( site, clientString );
	utstring_bincpy( clientString, "\r\n", 2 );
#if DEBUG_PRINT_CLIENT_PROTOCOL
	printf( "%10s: %s", "CLIENT_STR", utstring_body( clientString ));
#endif
	goto DONE;

ERR:
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

@param site the \p Sqrl_Site
@return pointer to a new UT_string object containing the client's body text
*/
 
UT_string *sqrl_site_client_body( Sqrl_Site *site ) 
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
	sqrl_sign( buffer, site->keys[SITE_KEY_SEC], site->keys[SITE_KEY_PUB], binSig );
	sqrl_b64u_encode_append( result, binSig, SQRL_SIG_SIZE );
	if( site->keys[SITE_KEY_LOOKUP][SITE_KEY_PSEC] ) {
		utstring_bincpy( result, "&pids=", 6 );
		sqrl_sign( buffer, site->keys[SITE_KEY_PSEC], site->keys[SITE_KEY_PPUB], binSig );
		sqrl_b64u_encode_append( result, binSig, SQRL_SIG_SIZE );
	}
	if( site->keys[SITE_KEY_LOOKUP][SITE_KEY_URSK] ) {
		utstring_bincpy( result, "&urs=", 5 );
		sqrl_sign( buffer, site->keys[SITE_KEY_URSK], site->keys[SITE_KEY_URPK], binSig );
		sqrl_b64u_encode_append( result, binSig, SQRL_SIG_SIZE );
	}

	utstring_free( buffer );
	return result;
}

static struct Sqrl_Site_List *SQRL_SITE_LIST = NULL;

int sqrl_site_count()
{
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.site );
    int i = 0;
    struct Sqrl_Site_List *list = SQRL_SITE_LIST;
    while( list ) {
        i++;
        list = list->next;
    }
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.site );
    return i;
}

Sqrl_Site *sqrl_client_site_create( SqrlTransaction *transaction )
{
	if( !transaction ) return NULL;
	Sqrl_Site *site = (Sqrl_Site*)calloc( 1, sizeof( Sqrl_Site ));
	char *tmpString;
	site->transaction = transaction;
	transaction->hold();
	site->currentTransaction = SQRL_TRANSACTION_AUTH_QUERY;
	site->previous_identity = -1;
	site->mutex = sqrl_mutex_create();

	if( transaction->getUri() ) {
		utstring_new( site->serverString );
		tmpString = transaction->getUri()->getChallenge();
		sqrl_b64u_encode( site->serverString, (uint8_t*)tmpString, strlen( tmpString ));
		free(tmpString);
		FLAG_SET( site->flags, SITE_FLAG_VALID_SERVER_STRING );
	}
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.site );
	struct Sqrl_Site_List *item = (Sqrl_Site_List*)calloc( 1, sizeof( struct Sqrl_Site_List ));
	struct Sqrl_Site_List *list = SQRL_SITE_LIST;
	item->site = site;
	if( ! SQRL_SITE_LIST ) {
		SQRL_SITE_LIST = item;
	} else {
		while( list->next ) {
			list = list->next;
		}
		list->next = item;
	}
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.site );
	return site;
}

static struct Sqrl_Site_List *_scsm( struct Sqrl_Site_List *cur, double now, bool forceDeleteAll )
{
	if( cur == NULL ) {
		// End of list
		return NULL;
	}

	sqrl_mutex_enter( cur->site->mutex );
	if( forceDeleteAll || (now - cur->site->lastAction) > SQRL_CLIENT_SITE_TIMEOUT ) {
		// Delete this one
		struct Sqrl_Site_List *next = cur->next;

		cur->site->transaction->release();
		cur->site->transaction = NULL;
		if( cur->site->serverFriendlyName ) {
			free( cur->site->serverFriendlyName );
		}
		if( cur->site->serverString ) {
			utstring_free( cur->site->serverString );
		}
		if( cur->site->clientString ) {
			utstring_free( cur->site->clientString );
		}
		sqrl_mutex_destroy( cur->site->mutex );
		sodium_memzero( cur->site->keys, sizeof( cur->site->keys ));
		free( cur->site );

		return _scsm( next, now, forceDeleteAll );
	}
	sqrl_mutex_leave( cur->site->mutex );

	// Continue checking list
	cur->next = _scsm( cur->next, now, forceDeleteAll );
	return cur;
}

void sqrl_client_site_maintenance( bool forceDeleteAll )
{
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.site );
	double now = sqrl_get_real_time();
	SQRL_SITE_LIST = _scsm( SQRL_SITE_LIST, now, forceDeleteAll );
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.site );
}

Sqrl_Transaction_Status sqrl_client_do_loop( Sqrl_Site *site )
{
	if( !site ) return SQRL_TRANSACTION_STATUS_FAILED;
	if( sqrl_site_generate_client_body( site )) {
		UT_string *bdy;
		bdy = sqrl_site_client_body( site );
		char *tmpString = site->transaction->getUri()->getUrl();
		sqrl_client_call_send(
			site->transaction, tmpString, strlen( tmpString ),
			utstring_body( bdy ), utstring_len( bdy ));
		free(tmpString);
		utstring_free( bdy );
	}
	return SQRL_TRANSACTION_STATUS_WORKING;
}

Sqrl_Transaction_Status sqrl_client_resume_transaction( SqrlTransaction *transaction, const char *response, size_t response_len )
{
	if( !transaction ) return SQRL_TRANSACTION_STATUS_FAILED;
	Sqrl_Site *site = NULL;

	// Retrieve an existing Sqrl_Site (if available)
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.site );
	struct Sqrl_Site_List *list = SQRL_SITE_LIST;
	while( list ) {
		if( list->site->transaction == transaction ) {
			site = list->site;
			break;
		}
		list = list->next;
	}
	if( site ) {
		site->lastAction = sqrl_get_real_time();
	}
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.site );

	if( site ) {
		if( response && response_len ) {
			sqrl_site_parse_result( site, response, response_len );
		}
	} else {
		// No existing site... Create a new one.
		site = sqrl_client_site_create( transaction );
	}
	
	if( !site ) goto ERR;
	if( !FLAG_CHECK( site->flags, SITE_FLAG_VALID_SERVER_STRING )) {
#if DEBUG_PRINT_CLIENT_PROTOCOL
		printf( "!VALID_SERVER_STRING\n" );
#endif
		goto ERR;
	}
	if( response && response_len ) {
		if( site->tif & SQRL_TIF_COMMAND_FAILURE ) {
			goto ERR;
		}

		switch( site->currentTransaction ) {
		case SQRL_TRANSACTION_AUTH_QUERY:
			if( (site->tif & SQRL_TIF_ID_MATCH) || (site->tif & SQRL_TIF_PREVIOUS_ID_MATCH) ) {
				// Already found a match.
				if( FLAG_CHECK( site->tif, SQRL_TIF_SQRL_DISABLED )) {
					if( transaction->getType() != SQRL_TRANSACTION_AUTH_ENABLE &&
						transaction->getType() != SQRL_TRANSACTION_AUTH_REMOVE ) {
						goto ERR;
					}
				}
				site->currentTransaction = transaction->getType();
			} else {
				// Identity not matched.
				if( site->previous_identity < 3 ) {
					// Try next most recent identity
					site->previous_identity++;
				} else {
					// Tried all previous identities
					site->previous_identity = 0;
					site->currentTransaction = transaction->getType();
					if( transaction->getType() != SQRL_TRANSACTION_AUTH_IDENT ) {
						goto ERR;
					}
					// If it's an ident, we'll continue (create new account)
				}
			}
			break;
		case SQRL_TRANSACTION_AUTH_IDENT:
			if( site->tif & SQRL_TIF_ID_MATCH ) {
				transaction->setStatus(SQRL_TRANSACTION_STATUS_SUCCESS);
			} else {
				transaction->setStatus(SQRL_TRANSACTION_STATUS_FAILED);
			}
			goto DONE;
		case SQRL_TRANSACTION_AUTH_DISABLE:
			if( FLAG_CHECK( site->tif, SQRL_TIF_SQRL_DISABLED )) {
				transaction->setStatus(SQRL_TRANSACTION_STATUS_SUCCESS);
			} else {
				transaction->setStatus(SQRL_TRANSACTION_STATUS_FAILED);
			}
			goto DONE;
		case SQRL_TRANSACTION_AUTH_ENABLE:
			if( !FLAG_CHECK( site->tif, SQRL_TIF_SQRL_DISABLED )) {
				transaction->setStatus(SQRL_TRANSACTION_STATUS_SUCCESS);
			} else {
				transaction->setStatus(SQRL_TRANSACTION_STATUS_FAILED);
			}
			goto DONE;
		case SQRL_TRANSACTION_AUTH_REMOVE:
			if( !FLAG_CHECK( site->tif, SQRL_TIF_ID_MATCH ) &&
				!FLAG_CHECK( site->tif, SQRL_TIF_PREVIOUS_ID_MATCH )) {
				transaction->setStatus(SQRL_TRANSACTION_STATUS_SUCCESS);
			} else {
				transaction->setStatus(SQRL_TRANSACTION_STATUS_FAILED);
			}
			goto DONE;
		default:
			break;
		}
	}
	FLAG_CLEAR( site->flags, SITE_FLAG_VALID_CLIENT_STRING );
	sqrl_client_do_loop( site );
	goto DONE;

ERR:
	transaction->setStatus(SQRL_TRANSACTION_STATUS_FAILED);

DONE:
	return transaction->getStatus();
}
