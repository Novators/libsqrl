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

SqrlBlock *SqrlBlock::create() {
	SqrlBlock *b = (SqrlBlock*)malloc( sizeof( SqrlBlock ) );
	new (b) SqrlBlock;
	return b;
}

SqrlBlock *SqrlBlock::create( uint16_t blockType, uint16_t blockLength ) {
	SqrlBlock *b = (SqrlBlock*)malloc( sizeof( SqrlBlock ) );
	new (b) SqrlBlock;
	if( b->init( blockType, blockLength ) ) {
		return b;
	}
	return b->release();
}

SqrlBlock::SqrlBlock()
{
	this->data = NULL;
	this->clear();
}

SqrlBlock *SqrlBlock::release() {
	this->~SqrlBlock();
	return NULL;
}

SqrlBlock::~SqrlBlock()
{
	if( this->data ) {
		free( this->data );
	}
	free( this );
}

void SqrlBlock::clear()
{
	this->blockLength = 0;
	this->blockType = 0;
	this->cur = 0;
	if (this->data) {
		free(this->data);
		this->data = NULL;
	}
}

bool SqrlBlock::init(uint16_t blockType, uint16_t blockLength)
{
	this->clear();
	if (this->data) {
		free(this->data);
		this->data = NULL;
	}
	this->blockLength = blockLength;
	this->blockType = blockType;
	if (blockLength > 0) {
		this->data = (uint8_t*)malloc(blockLength);
		if (this->data) {
			sqrl_mlock(this->data, blockLength);
			return true;
		}
	}
	return false;
}

bool SqrlBlock::resize(size_t new_size)
{
	if( new_size == 0 ) return false;
	if( new_size == this->blockLength ) return true;

	uint8_t *buf = (uint8_t*)malloc( new_size );
	if( !buf ) return false;

	if( new_size < this->blockLength ) {
		memcpy( buf, this->data, new_size );
	} else {
		memset( buf, 0, new_size );
		memcpy( buf, this->data, this->blockLength );
	}

	sqrl_munlock( this->data, this->blockLength );
	free( this->data );
	this->data = (uint8_t*)malloc( new_size );
	if( this->data ) {
		sqrl_mlock( this->data, new_size );
		this->blockLength = (uint16_t)new_size;
		if( this->cur >= this->blockLength ) {
			this->cur = this->blockLength - 1;
		}
		memcpy( this->data, buf, new_size );
	}
	memset( buf, 0, new_size );
	free( buf );
	return false;
}

uint16_t SqrlBlock::seek( uint16_t dest, bool offset )
{
	if (offset) {
		dest += this->cur;
	}
	if( dest < this->blockLength ) {
		this->cur = dest;
	}
	return this->cur;
}

uint16_t SqrlBlock::seekBack(uint16_t dest, bool offset)
{
	if (offset) {
		dest = this->cur - dest;
	} else {
		dest = this->blockLength - dest - 1;
	}
	if (dest > 0) {
		this->cur = dest;
	}
	return this->cur;
}

int SqrlBlock::write( uint8_t *data, size_t data_len )
{
	if( this->cur + data_len > this->blockLength ) return -1;
	memcpy( &this->data[this->cur], data, data_len );
	this->cur += (uint16_t)data_len;
	return (int)data_len;
}

int SqrlBlock::read( uint8_t *data, size_t data_len )
{
	if( this->cur + data_len > this->blockLength ) return -1;
	memcpy( data, &this->data[this->cur], data_len );
	this->cur += (uint16_t)data_len;
	return (int)data_len;
}

uint16_t SqrlBlock::readInt16()
{
	if( this->cur + 2 > this->blockLength ) return 0;
	uint8_t *b = (uint8_t*)(this->data + this->cur);
	uint16_t r = ((uint16_t)b[0]) | (((uint16_t)b[1]) << 8);
	this->cur += 2;
	return r;
}

bool SqrlBlock::writeInt16( uint16_t value )
{
	if( this->cur + 2 > this->blockLength ) return false;
	this->data[this->cur++] = value & 0xff;
	this->data[this->cur++] = value >> 8;
	return true;
}

uint32_t SqrlBlock::readInt32()
{
	if( this->cur + 4 > this->blockLength ) return 0;
	uint32_t r = (uint32_t)this->data[this->cur++];
	r |= ((uint32_t)this->data[this->cur++])<<8;
	r |= ((uint32_t)this->data[this->cur++])<<16;
	r |= ((uint32_t)this->data[this->cur++])<<24;
	return r;
}

bool SqrlBlock::writeInt32( uint32_t value )
{
	if( this->cur + 4 > this->blockLength ) return false;
	this->data[this->cur++] = (uint8_t)value;
	this->data[this->cur++] = (uint8_t)(value>>8);
	this->data[this->cur++] = (uint8_t)(value>>16);
	this->data[this->cur++] = (uint8_t)(value>>24);
	return true;
}

uint8_t SqrlBlock::readInt8()
{
	if( this->cur + 1 > this->blockLength ) return 0;
	return this->data[this->cur++];
}

bool SqrlBlock::writeInt8( uint8_t value )
{
	if( this->cur + 1 > this->blockLength ) return false;
	this->data[this->cur++] = value;
	return true;
}

SqrlString* SqrlBlock::getData(SqrlString *buf, bool append)
{
	if( buf ) {
		if( !append ) buf->clear();
	} else {
		if( this->blockLength > 0 )	buf = new SqrlString();
	}
	if (this->blockLength > 0) {
		buf->append( (uint8_t*)this->data, this->blockLength );
	} else {
		return NULL;
	}
	return buf;
}

uint8_t* SqrlBlock::getDataPointer( bool atCursor )
{
	if (atCursor) {
		return this->data + this->cur;
	} else {
		return this->data;
	}
}

uint16_t SqrlBlock::getBlockLength()
{
	return this->blockLength;
}

uint16_t SqrlBlock::getBlockType()
{
	return this->blockType;
}
