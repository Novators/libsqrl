#include "sqrl_internal.h"
#include "SqrlActionSave.h"
#include "SqrlUri.h"
#include "SqrlUser.h"
#include "SqrlClient.h"

SqrlActionSave::SqrlActionSave( SqrlUser *user, SqrlUri *uri ) 
	: SqrlIdentityAction( user ),
	buffer(NULL),
	buffer_len(0) {
	if( uri ) {
		this->uri = uri->copy();
		this->exportType = SQRL_EXPORT_ALL;
		this->encodingType = SQRL_ENCODING_BINARY;
	} else {
		this->uri = NULL;
		this->exportType = SQRL_EXPORT_ALL;
		this->encodingType = SQRL_ENCODING_BASE64;
	}
}

SqrlActionSave::SqrlActionSave( SqrlUser *user, const char *path ) 
	: SqrlIdentityAction( user ),
	buffer(NULL),
	buffer_len(NULL) {
	if( path ) {
		this->uri = SqrlUri::parse( path );
		this->exportType = SQRL_EXPORT_ALL;
		this->encodingType = SQRL_ENCODING_BINARY;
	} else {
		this->uri = NULL;
		this->exportType = SQRL_EXPORT_ALL;
		this->encodingType = SQRL_ENCODING_BASE64;
	}
}

void SqrlActionSave::run() {
	if( this->running || this->finished || this->runState < 0 ) return;
	this->running = true;
	if( this->uri ) {
		this->runState = this->user->save( this ) ? 1 : -1;
	} else {
		this->runState = this->user->saveToBuffer( this ) ? 1 : -1;
	}
	this->finished = true;
	SqrlClient::getClient()->onActionComplete( this );
	this->running = false;
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

