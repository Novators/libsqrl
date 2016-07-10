/** @file storage.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include <sodium.h>
#include <stdio.h>
#include "sqrl_internal.h"
#include "storage.h"

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



static struct S4Page * sqrl_page_create()
{
	struct S4Page *page = (struct S4Page*)sodium_malloc(sizeof(struct S4Page));
	page->nextPage = NULL;
	memset(page->index, 0, sizeof(struct S4Table) * BLOCKS_PER_PAGE);
	SQRL_STORAGE_LOCK(page);
	return page;
}

static struct S4Page * sqrl_page_destroy(struct S4Page *page)
{
	if (page) {
		SQRL_STORAGE_READ_ONLY(page);
		if (page->nextPage) {
			sqrl_page_destroy(page->nextPage);
		}
		sodium_free(page);
		page = NULL;
	}
	return page;
}

static bool find_block( struct S4Page *page, struct S4Pointer *pointer, uint16_t blockType )
{
	if( !pointer ) return false;

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

static bool allocate_block( struct S4Page *page, struct S4Pointer *pointer, uint16_t blockType, uint16_t blockLength )
{
	if( !pointer || !page ) return false;
	if( blockLength > PAGE_DATA_SIZE ) return false;

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
		page->nextPage = sqrl_page_create();
	}
	nextPage = page->nextPage;
	SQRL_STORAGE_LOCK( page );
	return allocate_block( nextPage, pointer, blockType, blockLength );
}

static bool sqrl_storage_block_remove( struct S4Page *page, uint16_t blockType )
{
	if( !page ) return false;
	struct S4Pointer pointer;
	if( find_block( page, &pointer, blockType )) {
		SQRL_STORAGE_READ_WRITE( pointer.page );
		pointer.index->active = 0;
		sodium_memzero( pointer.page->blocks + pointer.index->offset, pointer.index->blockLength );
		SQRL_STORAGE_LOCK( pointer.page );
		return true;
	}
	return false;
}

static bool sqrl_storage_block_put( struct S4Page *page, SqrlBlock *block )
{
	if( !page || !block ) return false;
	struct S4Pointer pointer;
	UT_string *data = block->getData(NULL);
	if( find_block( page, &pointer, block->getBlockType() )) {
		SQRL_STORAGE_READ_ONLY( pointer.page );
		if( pointer.index->blockLength <= block->getBlockLength() ) {
			SQRL_STORAGE_READ_WRITE( pointer.page );
			if( utstring_len(data) > 0 ) {
				memcpy( &pointer.page->blocks[pointer.index->offset], 
						utstring_body(data), utstring_len(data) );
				if( pointer.index->blockLength < utstring_len(data) ) {
					memset( (&pointer.page->blocks[pointer.index->offset]) + utstring_len(data),
						0, utstring_len(data) - pointer.index->blockLength );
				}
			}
			pointer.index->blockLength = block->getBlockLength();
			SQRL_STORAGE_LOCK( pointer.page );
			utstring_free(data);
			return true;
		}
		SQRL_STORAGE_LOCK( pointer.page );
		sqrl_storage_block_remove( page, block->getBlockType() );
	}
	if( allocate_block( page, &pointer, block->getBlockType(), block->getBlockLength() )) {
		SQRL_STORAGE_READ_WRITE( pointer.page );
		if( utstring_len(data) > 0 ) {
			memcpy( &pointer.page->blocks[pointer.index->offset], 
					utstring_body(data), utstring_len(data) );
		}
		SQRL_STORAGE_LOCK( pointer.page );
		utstring_free(data);
		return true;
	}
	utstring_free(data);
	return false;
}

static bool sqrl_storage_block_exists( struct S4Page *page, uint16_t blockType )
{
	if( !page ) return false;
	struct S4Pointer pointer;
	if( find_block( page, &pointer, blockType )) {
		return true;
	}
	return false;
}

static bool sqrl_storage_block_get( struct S4Page *page, SqrlBlock *block, uint16_t blockType )
{
	if( !page || !block ) return false;
	block->clear();
	struct S4Pointer pointer;
	if( find_block( page, &pointer, blockType )) {
		SQRL_STORAGE_READ_ONLY( pointer.page );
		if( block->init( pointer.index->blockType, pointer.index->blockLength )) {
			block->write(pointer.page->blocks + pointer.index->offset, block->getBlockLength());
			SQRL_STORAGE_LOCK( pointer.page );
			return true;
		}
		SQRL_STORAGE_LOCK( pointer.page );
		return false;
	}
	return false;
}

static bool sqrl_storage_load_from_buffer( struct S4Page *page, UT_string *buffer )
{
	uint8_t *cur, *end;
	bool retVal = true;
	SqrlBlock block = SqrlBlock();
	UT_string *buf = NULL;

	if( strncmp( utstring_body( buffer ), "sqrldata", 8 ) == 0 ) {
		buf = buffer;
	} else {
		utstring_new( buf );
		utstring_printf( buf, "sqrldata" );
		if( strncmp( utstring_body( buffer ), "SQRLDATA", 8 ) == 0) {
			sqrl_b64u_decode_append( buf, utstring_body(buffer)+8, utstring_len(buffer)-8 );
		} else if( strncmp( utstring_body( buffer ), "SQAC", 4) == 0 ) {
			sqrl_b64u_decode_append( buf, utstring_body(buffer), utstring_len(buffer) );
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
		uint16_t bl = readint_16(cur);
		uint16_t bt = readint_16(cur + 2);
		block.init(bt, bl);
		if( cur + bl > end ) {
			printf( "Invalid block Length\n" );
			goto ERR;
		}
		block.write(cur, bl);
		if( sqrl_storage_block_put( page, &block )) {
			cur += bl;
			continue;
		}
		goto ERR;
	}
	goto DONE;

ERR:
	retVal = false;

DONE:
	if( buf && buf != buffer ) {
		utstring_free( buf );
	}
	return retVal;
}

static bool sqrl_storage_load_from_file( struct S4Page *page, const char *filename )
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

	retVal = sqrl_storage_load_from_buffer( page, buf );
	utstring_free( buf );
	return retVal;
}

static bool sqrl_storage_save_to_buffer( 
	struct S4Page *page, 
	UT_string *buf, 
	Sqrl_Export etype, 
	Sqrl_Encoding encoding )
{
	UT_string *tmp;
	int i;
	utstring_new( tmp );

	if( etype == SQRL_EXPORT_RESCUE ) {
		SqrlBlock block = SqrlBlock();
		if( sqrl_storage_block_get( page, &block, SQRL_BLOCK_RESCUE )) {
			block.getData(tmp);
		}
		if( sqrl_storage_block_get( page, &block, SQRL_BLOCK_PREVIOUS )) {
			block.getData(tmp, true);
		}
	} else {
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
	if( encoding == SQRL_ENCODING_BASE64 ) {
		utstring_printf( buf, "SQRLDATA" );
		sqrl_b64u_encode_append( buf, (uint8_t*)(utstring_body( tmp )), utstring_len( tmp ));
	} else {
		utstring_printf( buf, "sqrldata" );
		utstring_concat( buf, tmp );
	}
	utstring_free( tmp );
	return true;
}

static int sqrl_storage_save_to_file( struct S4Page *page, const char *filename, Sqrl_Export etype, Sqrl_Encoding encoding )
{
	int retVal;
	UT_string *buf;
	utstring_new( buf );
	if( buf == NULL ) return -1;
	sqrl_storage_save_to_buffer( page, buf, etype, encoding );
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

static void sqrl_storage_unique_id(struct S4Page *page, char *unique_id )
{
	if( !unique_id ) return;
	SqrlBlock block = SqrlBlock();
	if( !page ) goto ERR;
	if( sqrl_storage_block_exists( page, SQRL_BLOCK_RESCUE &&
		sqrl_storage_block_get( page, &block, SQRL_BLOCK_RESCUE )))
	{
		if( block.getBlockLength() == 73 ) {
			UT_string *buf;
			utstring_new( buf );
			uint8_t tmp[SQRL_KEY_SIZE];
			block.seek(25);
			block.read(tmp, SQRL_KEY_SIZE);
			sqrl_b64u_encode( buf, tmp, SQRL_KEY_SIZE );
			strcpy( unique_id, utstring_body( buf ));
			utstring_free( buf );
			return;
		}
	}

ERR:
	memset( unique_id, 0, SQRL_UNIQUE_ID_LENGTH + 1 );
}

SqrlStorage::SqrlStorage()
{
	this->data = sqrl_page_create();
}

SqrlStorage::~SqrlStorage()
{
	SQRL_CAST_PAGE(page, this->data);
	page = sqrl_page_destroy(page);
}

bool SqrlStorage::hasBlock(uint16_t blockType)
{
	SQRL_CAST_PAGE(page, this->data);
	return sqrl_storage_block_exists(page, blockType);
}

bool SqrlStorage::getBlock(SqrlBlock *block, uint16_t blockType)
{
	SQRL_CAST_PAGE(page, this->data);
	return sqrl_storage_block_get(page, block, blockType);
}

bool SqrlStorage::putBlock(SqrlBlock *block)
{
	SQRL_CAST_PAGE(page, this->data);
	return sqrl_storage_block_put(page, block);
}

bool SqrlStorage::removeBlock(uint16_t blockType)
{
	SQRL_CAST_PAGE(page, this->data);
	return sqrl_storage_block_remove(page, blockType);
}

bool SqrlStorage::load(UT_string *buffer)
{
	SQRL_CAST_PAGE(page, this->data);
	return sqrl_storage_load_from_buffer(page, buffer);
}

bool SqrlStorage::load(SqrlUri *uri)
{
	SQRL_CAST_PAGE(page, this->data);
	if (uri->getScheme() != SQRL_SCHEME_FILE) return false;
	char *fn = uri->getChallenge();
	bool ret = sqrl_storage_load_from_file(page, fn);
	free(fn);
	return ret;
}

bool SqrlStorage::save(UT_string *buffer, Sqrl_Export etype, Sqrl_Encoding encoding)
{
	SQRL_CAST_PAGE(page, this->data);
	return sqrl_storage_save_to_buffer(page, buffer, etype, encoding);
}

bool SqrlStorage::save(SqrlUri *uri, Sqrl_Export etype, Sqrl_Encoding encoding)
{
	SQRL_CAST_PAGE(page, this->data);
	if (uri->getScheme() != SQRL_SCHEME_FILE) return false;
	char *fn = uri->getUrl();
	int ret = sqrl_storage_save_to_file(page, fn, etype, encoding);
	free(fn);
	return ret > 0;
}

void SqrlStorage::getUniqueId(char *unique_id)
{
	SQRL_CAST_PAGE(page, this->data);
	return sqrl_storage_unique_id(page, unique_id);
}