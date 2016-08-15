/** \file SqrlBlock.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include <new>
#include "sqrl_internal.h"
#include "SqrlBlock.h"

using libsqrl::SqrlBlock;
using libsqrl::SqrlString;

namespace libsqrl
{
    SqrlBlock::SqrlBlock() : SqrlString() {}

    SqrlBlock::SqrlBlock( SqrlString * original ) : SqrlString( original ) {
        this->cur = 4;
    }

    SqrlBlock::SqrlBlock( const uint8_t* data ) : SqrlString() {
        this->append( data, 2 );
        uint16_t len = this->readInt16( 0 );
        this->append( data + 2, len - 2 );
        this->cur = 4;
    }

    void SqrlBlock::init( uint16_t blockType, uint16_t blockLength ) {
        if( blockLength < 4 ) blockLength = 4;
        this->clear();
        this->cur = 0;
        if( blockLength > 0 ) {
            this->append( (char)0, blockLength );
            this->writeInt16( blockLength );
            this->writeInt16( blockType );
            this->cur = 4;
        }
    }

    bool SqrlBlock::resize( uint16_t new_size ) {
        if( new_size < 4 ) return false;
        if( new_size < this->length() ) {
            this->erase( new_size, this->length() );
            this->writeInt16( new_size, 0 );
            return true;
        }
        if( new_size > this->length() ) {
            this->append( (char)0, new_size - this->length() );
            this->writeInt16( new_size, 0 );
            return true;
        }
        return true;
    }

    uint16_t SqrlBlock::seek( uint16_t dest, bool offset ) {
        if( offset ) {
            dest += this->cur;
        }
        this->cur = dest;
        if( this->cur > (uint16_t)this->length() ) this->cur = (uint16_t)this->length();
        return this->cur;
    }

    uint16_t SqrlBlock::seekBack( uint16_t dest, bool offset ) {
        if( offset ) {
            if( this->cur > dest ) {
                this->cur -= dest;
            } else {
                this->cur = 0;
            }
        } else {
            if( dest < this->length() ) {
                this->cur = (uint16_t)this->length() - dest;
            } else {
                this->cur = 0;
            }
        }
        return this->cur;
    }

    int SqrlBlock::write( uint8_t *data, uint16_t data_len, uint16_t offset ) {
        bool updateCursor = (offset == UINT16_MAX);
        if( updateCursor ) {
            offset = this->cur;
        }
        if( data_len + offset > this->length() ) {
            this->append( (char)0, data_len + offset - this->length() );
            this->writeInt16( (uint16_t)this->length(), 0 );
        }
        if( data_len + offset > this->length() ) return -1;
        memcpy( (uint8_t*)this->myData + offset, data, data_len );
        if( updateCursor ) this->cur += (uint16_t)data_len;
        return (int)data_len;
    }

    int SqrlBlock::read( uint8_t *data, size_t data_len, uint16_t offset ) {
        bool updateCursor = (offset == UINT16_MAX);
        if( updateCursor ) offset = this->cur;
        if( offset + data_len > this->length() ) return -1;
        memcpy( data, (uint8_t*)this->myData + offset, data_len );
        if( updateCursor ) this->cur += (uint16_t)data_len;
        return (int)data_len;
    }

    uint16_t SqrlBlock::readInt16( uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            if( (o + 2) > this->length() ) return false;
            this->cur += 2;
        } else {
            o = offset;
            if( (o + 2) > this->length() ) return false;
        }
        uint8_t *d = (uint8_t*)this->myData + o;
        return ((uint16_t)d[0]) | (((uint16_t)d[1]) << 8);
    }

    bool SqrlBlock::writeInt16( uint16_t value, uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            if( (o + 2) > this->length() ) return false;
            this->cur += 2;
        } else {
            o = offset;
            if( (o + 2) > this->length() ) return false;
        }
        uint8_t *d = (uint8_t*)this->myData + o;
        d[0] = value & 0xff;
        d[1] = value >> 8;
        return true;
    }

    uint32_t SqrlBlock::readInt32( uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            if( (o + 4) > this->length() ) return 0;
            this->cur += 4;
        } else {
            o = offset;
            if( (o + 4) > this->length() ) return 0;
        }
        uint8_t *d = (uint8_t*)this->myData + o;

        uint32_t r = (uint32_t)d[0];
        r |= ((uint32_t)d[1]) << 8;
        r |= ((uint32_t)d[2]) << 16;
        r |= ((uint32_t)d[3]) << 24;
        return r;
    }

    bool SqrlBlock::writeInt32( uint32_t value, uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            if( (o + 4) > this->length() ) return false;
            this->cur += 4;
        } else {
            o = offset;
            if( (o + 4) > this->length() ) return false;
        }
        uint8_t *d = (uint8_t*)this->myData + o;

        d[0] = (uint8_t)value;
        d[1] = (uint8_t)(value >> 8);
        d[2] = (uint8_t)(value >> 16);
        d[3] = (uint8_t)(value >> 24);
        return true;
    }

    uint8_t SqrlBlock::readInt8( uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            if( (o + 1) > this->length() ) return 0;
            this->cur += 1;
        } else {
            o = offset;
            if( (o + 1) > this->length() ) return 0;
        }
        uint8_t *d = (uint8_t*)this->myData + o;
        return d[0];
    }

    bool SqrlBlock::writeInt8( uint8_t value, uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            if( (o + 1) > this->length() ) return false;
            this->cur += 1;
        } else {
            o = offset;
            if( (o + 1) > this->length() ) return false;
        }
        uint8_t *d = (uint8_t*)this->myData + o;

        d[0] = value;
        return true;
    }

    SqrlString* SqrlBlock::getData( SqrlString *buf, bool append ) {
        if( buf ) {
            if( !append ) buf->clear();
            buf->append( this );
            return buf;
        } else {
            buf = new SqrlString( this );
            return buf;
        }
    }

    uint8_t* SqrlBlock::getDataPointer( bool atCursor ) {
        if( atCursor ) {
            return (uint8_t*)this->myData + this->cur;
        } else {
            return (uint8_t*)this->myData;
        }
    }

    uint16_t SqrlBlock::getBlockLength() {
        return this->readInt16( 0 );
    }

    uint16_t SqrlBlock::getBlockType() {
        return this->readInt16( 2 );
    }
}

