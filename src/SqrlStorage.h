/** \file SqrlStorage.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLSTORAGE_H
#define SQRLSTORAGE_H

#include <stdint.h>
#include "sqrl.h"
#include "SqrlString.h"
#include "SqrlDeque.h"

namespace libsqrl
{
    /// <summary>Stores a collection of SqrlBlock objects, and imports / exports them in S4 format.</summary>
    class SqrlStorage
    {
    public:
        SqrlStorage();
        SqrlStorage( SqrlString *buffer );
        SqrlStorage( SqrlUri *uri );
        ~SqrlStorage();

        bool hasBlock( uint16_t blockType );
        bool getBlock( SqrlBlock *block, uint16_t blockType );
        bool putBlock( SqrlBlock *block );
        bool removeBlock( uint16_t blockType );
        void clear();

        bool load( SqrlString *buffer );
        bool load( SqrlUri *uri );

        SqrlString *save( Sqrl_Export etype, Sqrl_Encoding encoding );
        bool save( SqrlUri *uri, Sqrl_Export etype, Sqrl_Encoding encoding );

        void getUniqueId( SqrlString *unique_id );

    private:
        SqrlDeque<SqrlBlock*> data;
    };
}
#endif // SQRLSTORAGE_H
