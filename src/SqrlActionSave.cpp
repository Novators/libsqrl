/** @file SqrlActionSave.cpp
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionSave.h"
#include "SqrlUri.h"
#include "SqrlUser.h"
#include "SqrlClient.h"

SqrlActionSave::SqrlActionSave( SqrlUser *user, SqrlUri *uri, Sqrl_Export exportType, Sqrl_Encoding encodingType )
	: SqrlIdentityAction( user ),
	exportType( exportType ),
	encodingType( encodingType ),
	buffer(NULL),
	buffer_len( 0 ) {
	if( uri ) {
		this->uri = uri->copy();
	} else {
		this->uri = NULL;
	}
}

SqrlActionSave::SqrlActionSave( SqrlUser *user, const char *path, Sqrl_Export exportType, Sqrl_Encoding encodingType )
	: SqrlIdentityAction( user ),
	exportType( exportType ),
	encodingType( encodingType ),
	buffer(NULL),
	buffer_len(0) {
	if( path ) {
		this->uri = SqrlUri::parse( path );
	} else {
		this->uri = NULL;
	}
}

int SqrlActionSave::run( int cs ) {
	SqrlClient *client = SqrlClient::getClient();
	if( this->shouldCancel ) {
		return this->retActionComplete( SQRL_ACTION_CANCELED );
	}

	switch( cs ) {
	case 0:
		if( !this->user ) {
			client->callSelectUser( this );
			return cs;
		}
		return cs + 1;
	case 1:
		if( this->user->getPasswordLength() == 0 ) {
			client->callAuthenticationRequired( this, SQRL_CREDENTIAL_NEW_PASSWORD );
			return cs;
		}
		return cs + 1;
	case 2:
		if( this->uri ) {
			this->state = this->user->save( this ) ? 1 : -1;
		} else {
			this->state = this->user->saveToBuffer( this ) ? 1 : -1;
		}
		return this->retActionComplete( SQRL_ACTION_SUCCESS );
	default:
		// Invalid State
		return this->retActionComplete( SQRL_ACTION_FAIL );
	}
}

Sqrl_Export SqrlActionSave::getExportType() {
	return this->exportType;
}

void SqrlActionSave::setExportType( Sqrl_Export type ) {
	this->exportType = type;
}

Sqrl_Encoding SqrlActionSave::getEncodingType() {
	return this->encodingType;
}

void SqrlActionSave::setEncodingType( Sqrl_Encoding type ) {
	this->encodingType = type;
}

void SqrlActionSave::onRelease() {
	if( this->buffer ) { free( this->buffer ); }
	SqrlIdentityAction::onRelease();
}

size_t SqrlActionSave::getString( char *buf, size_t *len ) {
	size_t retVal = this->buffer_len;
	if( this->buffer ) {
		if( buf && len && *len ) {
			if( retVal < *len ) {
				memcpy( buf, this->buffer, retVal );
				buf[retVal] = 0;
				*len = retVal;
			} else {
				memcpy( buf, this->buffer, *len );
			}
		}
	}
	return retVal;
}

void SqrlActionSave::setString( const char *buf, size_t len ) {
	if( this->buffer ) {
		free( this->buffer );
	}
	this->buffer = NULL;
	this->buffer_len = 0;
	if( buf && len > 0 ) {
		this->buffer = (char*)malloc( len + 1 );
		memcpy( this->buffer, buf, len );
		this->buffer[len] = 0;
		this->buffer_len = len;
	}
}

