/** \file SqrlSiteAction.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlSiteAction.h"

char *SqrlSiteAction::getAltIdentity() {
	return this->altIdentity;
}

void SqrlSiteAction::setAltIdentity( const char *alt ) {
	if( this->altIdentity ) {
		free( this->altIdentity );
		this->altIdentity = NULL;
	}
	if( alt ) {
		size_t len = strlen( alt );
		this->altIdentity = (char*)malloc( len + 1 );
		if( this->altIdentity ) {
			memcpy( this->altIdentity, alt, len );
			this->altIdentity[len] = 0;
		}
	}
}

void SqrlSiteAction::onRelease() {
	if( this->altIdentity ) free( this->altIdentity );
}
