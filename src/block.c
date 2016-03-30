/** @file block.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include <sodium.h>
#include <stdio.h>
#include "sqrl_internal.h"

/**
Creates a new, empty \p Sqrl_Block

@return the new \p Sqrl_Block
*/
DLL_PUBLIC
Sqrl_Block *sqrl_block_create()
{
	Sqrl_Block *b = malloc( sizeof( Sqrl_Block ) );
	memset( b, 0, sizeof( Sqrl_Block ));
	return b;
}

/**
Frees memory associated with a \p Sqrl_Block

\warning If \p block was not properly created (cleared), this function may attempt
to free memory that has not been allocated!

@param block The \p Sqrl_Block to destroy
@return NULL pointer
*/
DLL_PUBLIC
Sqrl_Block *sqrl_block_destroy( Sqrl_Block *block )
{
	sqrl_block_free( block );
	free( block );
	return NULL;
}

/**
Clears a \p Sqrl_Block to zeros

This should be used to clear a local variable before use.

\warning If there is memory allocated at \p block->data, calling this function may result
in a memory leak!

@param block The \p Sqrl_Block to clear
*/
DLL_PUBLIC
void sqrl_block_clear( Sqrl_Block *block )
{
	memset( block, 0, sizeof( Sqrl_Block ));
}

/**
Initializes a \p Sqrl_Block

\warning This function attempts to free \p block->data.  Make certain that it is NULL after
creating a \p Sqrl_Block struct!

\warning This function allocates \p blockLength bytes of memory!  Be sure to 
\p sqrl_block_free it when you are done with it!  It is safe, though, to call 
\p sqrl_block_init on a block that's already been used.  It will be freed before 
it is reallocated.

@param block Pointer to the \p Sqrl_Block
@param blockType The type of block
@param blockLength The length of the block
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_block_init( Sqrl_Block *block, uint16_t blockType, uint16_t blockLength )
{
	sqrl_block_free( block );
	block->data = malloc( blockLength );
	if( block->data ) {
		block->blockType = blockType;
		block->blockLength = blockLength;
		block->cur = 0;
		sodium_mlock( block->data, blockLength );
		return true;
	}
	return false;
}

/**
Frees memory allocated to a \p Sqrl_Block

@param block The \p Sqrl_Block to free
*/
DLL_PUBLIC
void sqrl_block_free( Sqrl_Block *block )
{
	if( block->data ) {
		sodium_munlock( block->data, block->blockLength );
		free( block->data );
		block->data = NULL;
	}
	sodium_memzero( block, sizeof( Sqrl_Block ));
	//memset( block, 0, sizeof( Sqrl_Block ));
}

/**
Resizes a \p Sqrl_Block

@param block The \p Sqrl_Block to resize
@param new_size The size (in bytes) that the block should be
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_block_resize( Sqrl_Block *block, size_t new_size )
{
	if( new_size == 0 ) return false;
	if( new_size == block->blockLength ) return true;

	uint8_t *buf = malloc( new_size );
	if( !buf ) return false;

	if( new_size < block->blockLength ) {
		memcpy( buf, block->data, new_size );
	} else {
		memset( buf, 0, new_size );
		memcpy( buf, block->data, block->blockLength );
	}
	
	sodium_munlock( block->data, block->blockLength );
	free( block->data );
	block->data = malloc( new_size );
	sodium_mlock( block->data, new_size );
	block->blockLength = new_size;
	if( block->cur >= block->blockLength ) {
		block->cur = block->blockLength - 1;
	}
	memcpy( block->data, buf, new_size );
	memset( buf, 0, new_size );
	free( buf );
	return false;
}

/**
Moves the read/write cursor with a \p Sqrl_Block

@param block The \p Sqrl_Block
@param dest The offset where the cursor should point
@return The current position of the cursor.  If this != \p dest, something went wrong
*/
DLL_PUBLIC
uint16_t sqrl_block_seek( Sqrl_Block *block, uint16_t dest )
{
	if( dest < block->blockLength ) {
		block->cur = dest;
	}
	return block->cur;
}

/**
Writes data to a \p Sqrl_Block at the current cursor position.

@param block The \p Sqrl_Block
@param data Pointer to a buffer containing the data to be written
@param data_len Length (in bytes) of data to write
@return Number of bytes written; -1 on failure
*/
DLL_PUBLIC
int sqrl_block_write( Sqrl_Block *block, uint8_t *data, size_t data_len )
{
	if( block->cur + data_len > block->blockLength ) return -1;
	memcpy( &block->data[block->cur], data, data_len );
	block->cur += data_len;
	return data_len;
}

/**
Read bytes from a \p Sqrl_Block

@param block The \p Sqrl_Block
@param data Pointer to a buffer to hold the data (must be at least \p data_len bytes)
@param data_len Number of bytes to read
@return Number of bytes read; -1 on failure
*/
DLL_PUBLIC
int sqrl_block_read( Sqrl_Block *block, uint8_t *data, size_t data_len )
{
	if( block->cur + data_len > block->blockLength ) return -1;
	memcpy( data, &block->data[block->cur], data_len );
	block->cur += data_len;
	return data_len;
}

/**
Reads a 16-bit unsigned integer from a block at the cursor position.

Moves the cursor forward by 2.

@param block The \p Sqrl_Block
@return The value read from the block
*/
DLL_PUBLIC
uint16_t sqrl_block_read_int16( Sqrl_Block *block )
{
	if( block->cur + 2 > block->blockLength ) return 0;
	uint8_t *b = (uint8_t*)(block->data + block->cur);
	uint16_t r = b[0] | (b[1] << 8);
	block->cur += 2;
	return r;
}

/**
Writes a 16-bit unsigned integer to a block at the current cursor position.

Moves the cursor forward by 2.

@param block The \p Sqrl_Block
@param value The value to write
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_block_write_int16( Sqrl_Block *block, uint16_t value )
{
	if( block->cur + 2 > block->blockLength ) return false;
	block->data[block->cur++] = value & 0xff;
	block->data[block->cur++] = value >> 8;
	return true;
}

/**
Reads a 32-bit unsigned integer from a block at the cursor position.

Moves the cursor forward by 4.

@param block The \p Sqrl_Block
@return The value read from the block
*/
DLL_PUBLIC
uint32_t sqrl_block_read_int32( Sqrl_Block *block )
{
	if( block->cur + 4 > block->blockLength ) return 0;
	uint32_t r = block->data[block->cur++];
	r |= ((uint32_t)block->data[block->cur++])<<8;
	r |= ((uint32_t)block->data[block->cur++])<<16;
	r |= ((uint32_t)block->data[block->cur++])<<24;
	return r;
}

/**
Writes a 32-bit unsigned integer to a block at the current cursor position.

Moves the cursor forward by 4.

@param block The \p Sqrl_Block
@param value The value to write
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_block_write_int32( Sqrl_Block *block, uint32_t value )
{
	if( block->cur + 4 > block->blockLength ) return false;
	block->data[block->cur++] = (uint8_t)value;
	block->data[block->cur++] = (uint8_t)(value>>8);
	block->data[block->cur++] = (uint8_t)(value>>16);
	block->data[block->cur++] = (uint8_t)(value>>24);
	return true;	
}

/**
Reads an 8-bit unsigned integer from a block at the cursor position.

Moves the cursor forward by 1.

@param block The \p Sqrl_Block
@return The value read from the block
*/
DLL_PUBLIC
uint8_t sqrl_block_read_int8( Sqrl_Block *block )
{
	if( block->cur + 1 > block->blockLength ) return 0;
	return block->data[block->cur++];
}

/**
Writes an 8-bit unsigned integer to a block at the current cursor position.

Moves the cursor forward by 1.

@param block The \p Sqrl_Block
@param value The value to write
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_block_write_int8( Sqrl_Block *block, uint8_t value )
{
	if( block->cur + 1 > block->blockLength ) return false;
	block->data[block->cur++] = value;
	return true;
}