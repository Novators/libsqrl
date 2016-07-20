#pragma once

#include "sqrl.h"
#include "SqrlAction.h"

class DLL_PUBLIC SqrlSiteAction : public SqrlAction
{
public:
	void setAlternateIdentity( const char *altIdentity );
	char *getAltIdentity();
	void setAltIdentity( const char *alt );
	void dataReceived( const char *payload, size_t payload_len );
	void answer( Sqrl_Button answer );

protected:
	char *altIdentity;
	void onRelease();

};