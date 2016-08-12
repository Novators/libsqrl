/** \file SqrlActionSave.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlActionSave.h"
#include "SqrlUri.h"
#include "SqrlUser.h"
#include "SqrlClient.h"

namespace libsqrl
{
    SqrlActionSave::SqrlActionSave( SqrlUser *user, SqrlUri *uri, Sqrl_Export exportType, Sqrl_Encoding encodingType )
        : SqrlIdentityAction( user ),
        exportType( exportType ),
        encodingType( encodingType ),
        buffer( NULL ),
        buffer_len( 0 ) {
        if( uri ) {
            this->uri = new SqrlUri( uri );
        } else {
            this->uri = NULL;
        }
    }

    SqrlActionSave::SqrlActionSave( SqrlUser *user, const char *path, Sqrl_Export exportType, Sqrl_Encoding encodingType )
        : SqrlIdentityAction( user ),
        exportType( exportType ),
        encodingType( encodingType ),
        buffer( NULL ),
        buffer_len( 0 ) {
        if( path ) {
            SqrlString ps = SqrlString( path );
            this->uri = new SqrlUri( &ps );
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
                this->status = this->user->save( this ) ? SQRL_ACTION_SUCCESS : SQRL_ACTION_FAIL;
            } else {
                this->status = this->user->saveToBuffer( this ) ? SQRL_ACTION_SUCCESS : SQRL_ACTION_FAIL;
            }
            return cs + 1;
        case 3:
            return this->retActionComplete( this->status );
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
            if( this->buffer ) {
                memcpy( this->buffer, buf, len );
                this->buffer[len] = 0;
                this->buffer_len = len;
            }
        }
    }
}