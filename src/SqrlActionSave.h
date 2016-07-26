#pragma once

#include "sqrl.h"
#include "SqrlIdentityAction.h"

class DLL_PUBLIC SqrlActionSave : public SqrlIdentityAction
{
public:
	SqrlActionSave( SqrlUser *user, SqrlUri *uri = NULL, Sqrl_Export exportType = SQRL_EXPORT_ALL, Sqrl_Encoding encodingType = SQRL_ENCODING_BINARY );
	SqrlActionSave( SqrlUser *user, const char *path, Sqrl_Export exportType = SQRL_EXPORT_ALL, Sqrl_Encoding encodingType = SQRL_ENCODING_BINARY );
	Sqrl_Export getExportType();
	void setExportType( Sqrl_Export type );
	Sqrl_Encoding getEncodingType();
	void setEncodingType( Sqrl_Encoding type );
	size_t getString( char * buf, size_t * len );
	void setString( const char * buf, size_t len );

	int run( int cs );

protected:
	Sqrl_Export exportType;
	Sqrl_Encoding encodingType;
	char *buffer;
	size_t buffer_len;
	void onRelease();
};