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
		size_t len = strlen( alt ) + 1;
		this->altIdentity = (char*)malloc( len );
		strcpy_s( this->altIdentity, len, alt );
	}
}

void SqrlSiteAction::onRelease() {
	if( this->altIdentity ) free( this->altIdentity );
}