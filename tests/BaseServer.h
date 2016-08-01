#pragma once

#include "SqrlServer.h"

class BaseServer : public SqrlServer
{
public:
	BaseServer( const char *uri, const char *sfn, const char *passcode, size_t passcode_len ) 
		: SqrlServer( uri, sfn, passcode, passcode_len ) {

	}

	bool tryVerifyMAC( std::string *str ) {
		return this->verifyMAC( str );
	}

protected:
	bool onUserFind( const std::string *host, const std::string *idk, const std::string *pidk ) {
		return true;
	}

	bool onUserCreate( const std::string *host, const std::string *idk, const std::string *pidk ) {
		return true;
	}

	bool onUserUpdate( const std::string *host, const std::string *idk, const std::string *pidk ) {
		return true;
	}

	bool onUserDelete( const std::string *host, const std::string *idk, const std::string *pidk ) {
		return true;
	}

	bool onUserRekeyed( const std::string *host, const std::string *idk, const std::string *pidk ) {
		return true;
	}

	bool onUserIdentified( const std::string *host, const std::string *idk, const std::string *pidk ) {
		return true;
	}

	void onSend( const std::string *reply ) {
		printf( "srv -> client: %s\n", reply->data() );
	}

};

