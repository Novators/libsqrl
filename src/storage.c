/** @file storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include <sodium.h>
#include <stdio.h>
#include "sqrl_internal.h"

// TODO: Determine PAGE_SIZE at runtime?
#define PAGE_SIZE 4096
#define BLOCKS_PER_PAGE 15
#define PAGE_DATA_SIZE PAGE_SIZE - (8 * BLOCKS_PER_PAGE) - 10

#define SQRL_CAST_PAGE(a,b) struct S4Page *(a) = (struct S4Page*)(b)
#define SQRL_STORAGE_LOCK(x) sodium_mprotect_noaccess( (void*)(x) )
#define SQRL_STORAGE_READ_ONLY(x) sodium_mprotect_readonly( (void*)(x) )
#define SQRL_STORAGE_READ_WRITE(x) sodium_mprotect_readwrite( (void*)(x) )

#pragma pack(push,2)
struct S4Table {
	uint16_t blockLength;
	uint16_t blockType;
	uint16_t offset;
	uint16_t active : 1;
	uint16_t allocated : 1;
};

#pragma pack(8)
struct S4Page {
	struct S4Table index[BLOCKS_PER_PAGE];
	struct S4Page *nextPage;
	// 4 bytes padding on 32-bit systems
	uint8_t blocks[PAGE_DATA_SIZE];
};
#pragma pack(pop)

struct S4Pointer {
	struct S4Table *index;
	struct S4Page *page;
};

/**
Allocates and Initializes a new \p Sqrl_Storage object.

@return The new \p Sqrl_Storage object.
*/
DLL_PUBLIC
Sqrl_Storage sqrl_storage_create()
{
	struct S4Page *page = sodium_malloc( sizeof( struct S4Page ));
	if( !page ) return NULL;
	page->nextPage = NULL;
	memset( page->index, 0, sizeof( struct S4Table ) * BLOCKS_PER_PAGE );	
	SQRL_STORAGE_LOCK( page );
	return (Sqrl_Storage)page;
}

/**
Securely erase and free a \p Sqrl_Storage object.

@param storage The \p Sqrl_Storage object to destroy
@return NULL pointer
*/
DLL_PUBLIC
Sqrl_Storage sqrl_storage_destroy( Sqrl_Storage storage )
{
	SQRL_CAST_PAGE(page,storage);
	if( page ) {
		SQRL_STORAGE_READ_ONLY( page );
		if( page->nextPage ) {
			sqrl_storage_destroy( (Sqrl_Storage)page->nextPage );
		}
		sodium_free( page );
		page = NULL;
	}
	return page;
}

bool find_block( Sqrl_Storage storage, struct S4Pointer *pointer, uint16_t blockType )
{
	if( !pointer ) return false;

	SQRL_CAST_PAGE(page,storage);
	struct S4Page *nextPage = NULL;

	int i;
	while( page ) {
		SQRL_STORAGE_READ_ONLY( page );
		for( i = 0; i < BLOCKS_PER_PAGE; i++ ) {
			if( page->index[i].blockType == blockType && page->index[i].active ) {
				pointer->index = &page->index[i];
				pointer->page = page;
				SQRL_STORAGE_LOCK( page );
				return true;
			}
		}
		nextPage = page->nextPage;
		SQRL_STORAGE_LOCK( page );
		page = nextPage;
	}
	return false;
}

bool allocate_block( Sqrl_Storage storage, struct S4Pointer *pointer, uint16_t blockType, uint16_t blockLength )
{
	if( !pointer || !storage ) return false;
	if( blockLength > PAGE_DATA_SIZE ) return false;

	SQRL_CAST_PAGE(page,storage);
	struct S4Page *nextPage;
	uint16_t lastOffset = 0;
	uint16_t lastLength = 0;
	int i;

	SQRL_STORAGE_READ_ONLY( page );
	for( i = 0; i < BLOCKS_PER_PAGE; i++ ) {
		if( page->index[i].allocated ) {
			if( page->index[i].active ) {
				lastOffset = page->index[i].offset;
				lastLength = page->index[i].blockLength;
				continue;
			}
			if( lastOffset + lastLength + blockLength 
				<= page->index[i].blockLength ) {
				SQRL_STORAGE_READ_WRITE( page );
				page->index[i].offset = lastOffset + lastLength;
				page->index[i].blockLength = blockLength;
				page->index[i].blockType = blockType;
				page->index[i].active = 1;
				pointer->index = &page->index[i];
				pointer->page = page;
				SQRL_STORAGE_LOCK( page );
				return true;
			}
			continue;
		} else if( lastOffset + lastLength + blockLength 
			<= PAGE_DATA_SIZE ) {
			SQRL_STORAGE_READ_WRITE( page );
			page->index[i].allocated = 1;
			page->index[i].active = 1;
			page->index[i].offset = lastOffset + lastLength;
			page->index[i].blockLength = blockLength;
			page->index[i].blockType = blockType;
			pointer->index = &page->index[i];
			pointer->page = page;
			SQRL_STORAGE_LOCK( page );
			return true;
		} else {
			break;
		}
	}
	if( !page->nextPage ) {
		SQRL_STORAGE_READ_WRITE( page );
		page->nextPage = (struct S4Page*)sqrl_storage_create();
	}
	nextPage = page->nextPage;
	SQRL_STORAGE_LOCK( page );
	return allocate_block( nextPage, pointer, blockType, blockLength );
}

/**
Removes a block from storage.

@param storage The \p Sqrl_Storage object
@param blockType The type of block to remove
@return TRUE on success, FALSE if not found
*/
DLL_PUBLIC
bool sqrl_storage_block_remove( Sqrl_Storage storage, uint16_t blockType )
{
	if( !storage ) return false;
	struct S4Pointer pointer;
	if( find_block( storage, &pointer, blockType )) {
		SQRL_STORAGE_READ_WRITE( pointer.page );
		pointer.index->active = 0;
		sodium_memzero( pointer.page->blocks + pointer.index->offset, pointer.index->blockLength );
		SQRL_STORAGE_LOCK( pointer.page );
		return true;
	}
	return false;
}

/**
Adds a block to storage.

\warning If a block already exists in \p storage, it will be overwritten.

@param storage The \p Sqrl_Storage object
@param block Pointer to a \p Sqrl_Block containing the data to add to \p storage
@return TRUE on success, FALSE on failure
*/
DLL_PUBLIC
bool sqrl_storage_block_put( Sqrl_Storage storage, Sqrl_Block *block )
{
	if( !storage || !block ) return false;
	struct S4Pointer pointer;
	if( find_block( storage, &pointer, block->blockType )) {
		SQRL_STORAGE_READ_ONLY( pointer.page );
		if( pointer.index->blockLength <= block->blockLength ) {
			SQRL_STORAGE_READ_WRITE( pointer.page );
			if( block->data ) {
				memcpy( &pointer.page->blocks[pointer.index->offset], 
						block->data, block->blockLength );
				if( pointer.index->blockLength < block->blockLength ) {
					memset( (&pointer.page->blocks[pointer.index->offset]) + block->blockLength,
						0, block->blockLength - pointer.index->blockLength );
				}
			}
			pointer.index->blockLength = block->blockLength;
			SQRL_STORAGE_LOCK( pointer.page );
			return true;
		}
		SQRL_STORAGE_LOCK( pointer.page );
		sqrl_storage_block_remove( storage, block->blockType );
	}
	if( allocate_block( storage, &pointer, block->blockType, block->blockLength )) {
		SQRL_STORAGE_READ_WRITE( pointer.page );
		if( block->data ) {
			memcpy( &pointer.page->blocks[pointer.index->offset], 
					block->data, block->blockLength );
		}
		SQRL_STORAGE_LOCK( pointer.page );
		return true;
	}
	return false;
}

/** 
Checks to see if a block exists in storage.

@param storage The \p Sqrl_Storage object
@param blockType The type of block to check for
@return TRUE is \p storage contains a block of type \p blockType; FALSE if not
*/
DLL_PUBLIC
bool sqrl_storage_block_exists( Sqrl_Storage storage, uint16_t blockType )
{
	if( !storage ) return false;
	struct S4Pointer pointer;
	if( find_block( storage, &pointer, blockType )) {
		return true;
	}
	return false;
}

/**
Retrieves the contents of a block from storage.

@param storage The \p Sqrl_Storage object
@param block Pointer to a \p Sqrl_Block to populate
@param blockType The type of block to retrieve
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_storage_block_get( Sqrl_Storage storage, Sqrl_Block *block, uint16_t blockType )
{
	if( !storage || !block ) return false;
	sqrl_block_free( block );
	struct S4Pointer pointer;
	if( find_block( storage, &pointer, blockType )) {
		SQRL_STORAGE_READ_ONLY( pointer.page );
		if( sqrl_block_init( block, 
				pointer.index->blockType, pointer.index->blockLength )) {
			memcpy( block->data, pointer.page->blocks + pointer.index->offset, block->blockLength );
			SQRL_STORAGE_LOCK( pointer.page );
			return true;
		}
		SQRL_STORAGE_LOCK( pointer.page );
		return false;
	}
	return false;
}

/**
Loads data from a buffer into storage

\warning Does not clear the storage first, but does overwrite blocks of the same type.

@param storage The \p Sqrl_Storage object
@param buffer A UT_string buffer
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_storage_load_from_buffer( Sqrl_Storage storage, UT_string *buffer )
{
	uint8_t *cur, *end;
	bool retVal = true;
	Sqrl_Block block;
	memset( &block, 0, sizeof( Sqrl_Block ));
	UT_string *buf = NULL;

	if( strncmp( utstring_body( buffer ), "sqrldata", 8 ) == 0 ) {
		buf = buffer;
	} else {
		utstring_new( buf );
		utstring_printf( buf, "sqrldata" );
		if( strncmp( utstring_body( buffer ), "SQRLDATA", 8 ) == 0) {
			sqrl_b64u_decode_append( buf, utstring_body(buffer)+8, utstring_len(buffer)-8 );
		} else if( strncmp( utstring_body( buffer ), "SQAC", 4 ) == 0 ) {
			sqrl_b64u_decode_append( buf, utstring_body(buffer), utstring_len(buffer) );
		} else if( utstring_len( buffer ) == sqrl_b56c_validate( NULL, utstring_body( buffer ), utstring_len( buffer ), false )) {
			sqrl_b56c_decode_append( buf, utstring_body(buffer), utstring_len(buffer) );
		} else {
			printf( "Unrecognized format\n" );
			utstring_free(buf);
			return false;
		}
	}

	cur = (uint8_t*)(utstring_body( buf ));
	end = cur + utstring_len( buf );
	cur += 8; // skip "sqrldata"

	while( cur + 4 < end ) {
		block.blockLength = readint_16( cur );
		block.blockType = readint_16( cur+2 );
		//printf( "Found block %u of length %u.\n", block.blockType, block.blockLength );
		if( cur + block.blockLength > end ) {
			printf( "Invalid block Length\n" );
			goto ERROR;
		}
		block.data = cur;
		if( sqrl_storage_block_put( storage, &block )) {
			cur += block.blockLength;
			continue;
		}
		goto ERROR;
	}
	goto DONE;

ERROR:
	retVal = false;

DONE:
	if( buf && buf != buffer ) {
		utstring_free( buf );
	}
	return retVal;
}

/**
Loads data from a file into storage

\warning Does not clear the storage first, but does overwrite blocks of the same type.

@param storage The \p Sqrl_Storage object
@param filename The path of the file to load
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_storage_load_from_file( Sqrl_Storage storage, const char *filename )
{
	uint8_t tmp[256];
	size_t bytesRead;
	bool retVal;
	FILE *fp = fopen( filename, "rb" );
	if( !fp ) return false;

	UT_string *buf;
	utstring_new( buf );

	while( !feof( fp )) {
		bytesRead = fread( &tmp, 1, 256, fp );
		if( bytesRead > 0 ) {
			utstring_bincpy( buf, tmp, bytesRead );
		}
	}
	fclose( fp );

	retVal = sqrl_storage_load_from_buffer( storage, buf );
	utstring_free( buf );
	return retVal;
}

/**
Saves data from storage into a buffer

@param storage The \p Sqrl_Storage object
@param buf A UT_string buffer
@param etype The type of export to perform
@param encoding the type of encoding to use
@return TRUE on success; FALSE on failure
*/
DLL_PUBLIC
bool sqrl_storage_save_to_buffer( 
	Sqrl_Storage storage, 
	UT_string *buf, 
	Sqrl_Export etype, 
	Sqrl_Encoding encoding )
{
	UT_string *tmp;
	int i;
	utstring_new( tmp );

	if( etype == SQRL_EXPORT_RESCUE ) {
		Sqrl_Block block;
		memset( &block, 0, sizeof( Sqrl_Block ));
		if( sqrl_storage_block_get( storage, &block, SQRL_BLOCK_RESCUE )) {
			utstring_bincpy( tmp, block.data, block.blockLength );
			sqrl_block_free( &block );
		}
		if( sqrl_storage_block_get( storage, &block, SQRL_BLOCK_PREVIOUS )) {
			utstring_bincpy( tmp, block.data, block.blockLength );
			sqrl_block_free( &block );
		}
	} else {
		SQRL_CAST_PAGE(page,storage);
		struct S4Page *nextPage;
		while( page ) {
			SQRL_STORAGE_READ_ONLY( page );
			for( i = 0; i < BLOCKS_PER_PAGE; i++ ) {
				if( page->index[i].active ) {
					utstring_bincpy( tmp, page->blocks + page->index[i].offset, page->index[i].blockLength );
				}
			}
			nextPage = page->nextPage;
			SQRL_STORAGE_LOCK( page );
			page = nextPage;
		}
	}

	utstring_clear( buf );
	if( encoding == SQRL_ENCODING_BASE56 ) {
	  sqrl_b56c_encode_append( buf, (uint8_t*)(utstring_body( tmp )), utstring_len( tmp ));
	} else if( encoding == SQRL_ENCODING_BASE64 ) {
		utstring_printf( buf, "SQRLDATA" );
		sqrl_b64u_encode_append( buf, (uint8_t*)(utstring_body( tmp )), utstring_len( tmp ));
	} else {
		utstring_printf( buf, "sqrldata" );
		utstring_concat( buf, tmp );
	}
	utstring_free( tmp );
	return true;
}

/**
Saves data from storage to a file

@param storage The \p Sqrl_Storage object
@param filename The path of the file to save
@param etype The type of export to perform
@param encoding the type of encoding to use
@return Number of bytes written.  -1 indicates failure.
*/
DLL_PUBLIC
int sqrl_storage_save_to_file( Sqrl_Storage storage, const char *filename, Sqrl_Export etype, Sqrl_Encoding encoding )
{
	int retVal;
	UT_string *buf;
	utstring_new( buf );
	if( buf == NULL ) return -1;
	sqrl_storage_save_to_buffer( storage, buf, etype, encoding );
	FILE *fp = fopen( filename, "wb" );
	if( !fp ) {
		utstring_free( buf );
		return -1;
	}
	retVal = fwrite( utstring_body(buf), 1, utstring_len(buf), fp );
	fclose(fp);
	if( retVal != utstring_len( buf )) retVal = -1;
	utstring_free( buf );
	return retVal;
}

void sqrl_storage_unique_id( Sqrl_Storage storage, char *unique_id )
{
	if( !unique_id ) return;
	Sqrl_Block block;
	memset( &block, 0, sizeof( Sqrl_Block ));
	if( !storage ) goto ERROR;
	if( sqrl_storage_block_exists( storage, SQRL_BLOCK_RESCUE &&
		sqrl_storage_block_get( storage, &block, SQRL_BLOCK_RESCUE )))
	{
		if( block.blockLength == 73 ) {
			UT_string *buf;
			utstring_new( buf );
			sqrl_b64u_encode( buf, block.data + 25, SQRL_KEY_SIZE );
			strcpy( unique_id, utstring_body( buf ));
			utstring_free( buf );
			goto DONE;
		}
	}

ERROR:
	memset( unique_id, 0, SQRL_UNIQUE_ID_LENGTH + 1 );
DONE:
	sqrl_block_free( &block );
}
