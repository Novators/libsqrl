/** \file SqrlActionSave.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLACTIONSAVE_H
#define SQRLACTIONSAVE_H

#include "sqrl.h"
#include "SqrlIdentityAction.h"

namespace libsqrl
{
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
}
#endif // SQRLACTIONSAVE_H
