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
    /// <summary>Default constructor.</summary>
    SqrlBlock::SqrlBlock() : SqrlString() {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.  Creates a SqrlBlock with the contents of a SqrlString 
    ///          (or another SqrlBlock).</summary>
    ///
    /// <param name="original">[in] If non-null, the SqrlString or SqrlBlock to copy.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlBlock::SqrlBlock( const SqrlString * original ) : SqrlString( original ) {
        this->cur = (this->length() > 4) ? 4 : (uint16_t)this->length();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.  Creates a SqrlBlock from raw data.</summary>
    ///
    /// <param name="data">The data.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlBlock::SqrlBlock( const uint8_t* data ) : SqrlString() {
        this->append( data, 2 );
        uint16_t len = this->readInt16( 0 );
        if( len > 4096 ) {
            // Sanity check failed!  This is too long to be a proper block!
            this->writeInt16( 0, 0 );
            this->cur = 2;
            return;
        }
        this->append( data + 2, len - 2 );
        this->cur = 4;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears and Initializes a SqrlBlock.</summary>
    ///
    /// <param name="blockType">  Type of the block.</param>
    /// <param name="blockLength">Length of the block.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void SqrlBlock::init( uint16_t blockType, uint16_t blockLength ) {
        if( blockLength < 4 ) blockLength = 4;
        this->clear();
        this->append( (char)0, blockLength );
        this->writeInt16( blockLength, 0 );
        this->writeInt16( blockType, 2 );
        this->cur = 4;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Moves the read/write cursor forward.</summary>
    ///
    /// <param name="dest">  Destination.</param>
    /// <param name="offset">if true, moves from current cursor location.
    ///                      if false, moves from beginning of block.</param>
    ///
    /// <returns>The updated cursor position.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    uint16_t SqrlBlock::seek( uint16_t dest, bool offset ) {
        if( offset ) {
            dest += this->cur;
        }
        this->cur = dest;
        if( this->cur > (uint16_t)this->length() ) this->cur = (uint16_t)this->length();
        return this->cur;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Moves the read/write cursor backwards.</summary>
    ///
    /// <param name="dest">  Destination.</param>
    /// <param name="offset">If true, moves from current cursor location.
    ///                      If false, moves from end of block.</param>
    ///
    /// <returns>The updated cursor position.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Writes data to the block, growing the block if needed.</summary>
    ///
    /// <param name="data">    [in] The data to write.</param>
    /// <param name="data_len">Length of the data.</param>
    /// <param name="offset">  (Optional) If specified, the position to write data.
    ///                        If unspecified, data will be written at the current cursor position,
    ///                        and the cursor will be updated.</param>
    ///
    /// <returns>The length of data actually written, or -1 on error.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    int SqrlBlock::write( const uint8_t *data, uint16_t data_len, uint16_t offset ) {
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Reads data from the block.</summary>
    ///
    /// <param name="data">    [out] A buffer to hold the read data.</param>
    /// <param name="data_len">Length of the data.</param>
    /// <param name="offset">  (Optional) The position to begin reading from.
    ///                        If unspecified, read begins at current cursor position, and the 
    ///                        cursor will be updated.</param>
    ///
    /// <returns>Number of bytes read, or -1 on error.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    int SqrlBlock::read( uint8_t *data, size_t data_len, uint16_t offset ) {
        bool updateCursor = (offset == UINT16_MAX);
        if( updateCursor ) offset = this->cur;
        if( offset + data_len > this->length() ) return -1;
        memcpy( data, (uint8_t*)this->myData + offset, data_len );
        if( updateCursor ) this->cur += (uint16_t)data_len;
        return (int)data_len;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Reads an unsigned 16 bit integer from the block.</summary>
    ///
    /// <param name="offset">(Optional) The position to begin reading from.
    ///                      If unspecified, reading begins at the current cursos position,
    ///                      and the cursor will be moved forward.</param>
    ///
    /// <returns>An uint16_t.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Writes an unsigned 16 bit integer to the block, growing the block if needed.</summary>
    ///
    /// <param name="value"> The value.</param>
    /// <param name="offset">(Optional) The position to begin reading from.
    ///                      If unspecified, reading begins at the current cursos position,
    ///                      and the cursor will be moved forward.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlBlock::writeInt16( uint16_t value, uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            this->cur += 2;
        } else {
            o = offset;
        }
        if( (o + 2) > this->length() ) {
            this->append( (char)0, o + 2 - this->length() );
            this->writeInt16( (uint16_t)this->length(), 0 );
        }
        uint8_t *d = (uint8_t*)this->myData + o;
        d[0] = value & 0xff;
        d[1] = value >> 8;
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Reads an unsigned 32 bit integer from the block.</summary>
    ///
    /// <param name="offset">(Optional) The position to begin reading from.
    ///                      If unspecified, reading begins at the current cursos position,
    ///                      and the cursor will be moved forward.</param>
    ///
    /// <returns>An uint32_t.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Writes an unsigned 32 bit integer to the block, growing the block if needed.</summary>
    ///
    /// <param name="value"> The value.</param>
    /// <param name="offset">(Optional) The position to begin reading from.
    ///                      If unspecified, reading begins at the current cursos position,
    ///                      and the cursor will be moved forward.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlBlock::writeInt32( uint32_t value, uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            this->cur += 4;
        } else {
            o = offset;
        }
        if( (o + 4) > this->length() ) {
            this->append( (char)0, o + 4 - this->length() );
            this->writeInt16( (uint16_t)this->length(), 0 );
        }

        uint8_t *d = (uint8_t*)this->myData + o;

        d[0] = (uint8_t)value;
        d[1] = (uint8_t)(value >> 8);
        d[2] = (uint8_t)(value >> 16);
        d[3] = (uint8_t)(value >> 24);
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Reads a byte from the block.</summary>
    ///
    /// <param name="offset">(Optional) The position to begin reading from.
    ///                      If unspecified, reading begins at the current cursos position,
    ///                      and the cursor will be moved forward.</param>
    ///
    /// <returns>An uint8_t.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Writes a byte to the block, growing the block if needed.</summary>
    ///
    /// <param name="value"> The value.</param>
    /// <param name="offset">(Optional) The position to begin reading from.
    ///                      If unspecified, reading begins at the current cursos position,
    ///                      and the cursor will be moved forward.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlBlock::writeInt8( uint8_t value, uint16_t offset ) {
        size_t o;
        if( offset == UINT16_MAX ) {
            o = this->cur;
            this->cur += 1;
        } else {
            o = offset;
        }
        if( (o + 1) > this->length() ) {
            this->append( (char)0, o + 1 - this->length() );
            this->writeInt16( (uint16_t)this->length(), 0 );
        }

        uint8_t *d = (uint8_t*)this->myData + o;

        d[0] = value;
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets a copy of the data contained within this SqrlBlock.</summary>
    ///
    /// <param name="buf">   [out] (Optional) A SqrlString to hold the data.
    ///                      If unspecified, a new SqrlString will be created.  Caller is responsible
    ///                      for deleting the new SqrlString.</param>
    /// <param name="append">true to append.</param>
    ///
    /// <returns>Pointer to SqrlString instance containing the data.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets a pointer to the data inside this SqrlBlock.</summary>
    /// 
    /// <remarks>Careful, modifying the data at the returned pointer location is not recommended.</remarks>
    ///
    /// <param name="atCursor">(Optional) If true, points to the current cursor position.
    ///                        If false or unspecified, points to the beginning of the block.</param>
    ///
    /// <returns>A pointer to this SqrlBlock's data.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    uint8_t* SqrlBlock::getDataPointer( bool atCursor ) {
        if( atCursor ) {
            return (uint8_t*)this->myData + this->cur;
        } else {
            return (uint8_t*)this->myData;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the type of the block.</summary>
    ///
    /// <returns>The block type.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    uint16_t SqrlBlock::getBlockType() {
        return this->readInt16( 2 );
    }
}

