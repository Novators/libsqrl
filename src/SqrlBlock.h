/** \file SqrlBlock.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLBLOCK_H
#define SQRLBLOCK_H

#include <stdint.h>
#include "sqrl.h"
#include "SqrlString.h"

namespace libsqrl
{
    /// <summary>Represents an S4 block.</summary>
    class DLL_PUBLIC SqrlBlock : public SqrlString
    {
    public:
        SqrlBlock();
        SqrlBlock( const SqrlString *original );
        SqrlBlock( const uint8_t* data );
        void        init( uint16_t blockType, uint16_t blockLength );
        int         read( uint8_t *data, size_t data_len, uint16_t offset = UINT16_MAX );
        uint16_t    readInt16( uint16_t offset = UINT16_MAX );
        uint32_t    readInt32( uint16_t offset = UINT16_MAX );
        uint8_t     readInt8( uint16_t offset = UINT16_MAX );
        uint16_t    seek( uint16_t dest, bool offset = false );
        uint16_t	seekBack( uint16_t dest, bool offset = false );
        int         write( const uint8_t *data, uint16_t data_len, uint16_t offset = UINT16_MAX );
        bool        writeInt16( uint16_t value, uint16_t offset = UINT16_MAX );
        bool        writeInt32( uint32_t value, uint16_t offset = UINT16_MAX );
        bool        writeInt8( uint8_t value, uint16_t offset = UINT16_MAX );
        SqrlString*	getData( SqrlString *buf, bool append = false );
        uint8_t*	getDataPointer( bool atCursor = false );
        uint16_t	getBlockType();

    private:
        uint16_t cur;
    };
}
#endif // SQRLBLOCK_H
