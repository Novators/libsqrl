/** \file SqrlStorage.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlStorage.h"
#include "SqrlBlock.h"
#include "SqrlUri.h"
#include "SqrlBase64.h"
#include <new>

namespace libsqrl
{
    // TODO: Determine PAGE_SIZE at runtime?
#define PAGE_SIZE 4096
#define BLOCKS_PER_PAGE 15
#define PAGE_DATA_SIZE PAGE_SIZE - (8 * BLOCKS_PER_PAGE) - 10

#define SQRL_CAST_PAGE(a,b) struct S4Page *(a) = (struct S4Page*)(b)
#define SQRL_STORAGE_LOCK(x) sqrl_mprotect_noaccess( (void*)(x) )
#define SQRL_STORAGE_READ_ONLY(x) sqrl_mprotect_readonly( (void*)(x) )
#define SQRL_STORAGE_READ_WRITE(x) sqrl_mprotect_readwrite( (void*)(x) )

#pragma pack(push,2)
    struct S4Table
    {
        uint16_t blockLength;
        uint16_t blockType;
        uint16_t offset;
        uint16_t active : 1;
        uint16_t allocated : 1;
    };

#pragma pack(8)
    struct S4Page
    {
        struct S4Table index[BLOCKS_PER_PAGE];
        struct S4Page *nextPage;
        // 4 bytes padding on 32-bit systems
        uint8_t blocks[PAGE_DATA_SIZE];
    };
#pragma pack(pop)

    struct S4Pointer
    {
        struct S4Table *index;
        struct S4Page *page;
    };



    static struct S4Page * sqrl_page_create() {
        struct S4Page *page = (struct S4Page*)sqrl_malloc( sizeof( struct S4Page ) );
        page->nextPage = NULL;
        memset( page->index, 0, sizeof( struct S4Table ) * BLOCKS_PER_PAGE );
        SQRL_STORAGE_LOCK( page );
        return page;
    }

    static struct S4Page * sqrl_page_destroy( struct S4Page *page ) {
        if( page ) {
            SQRL_STORAGE_READ_ONLY( page );
            if( page->nextPage ) {
                sqrl_page_destroy( page->nextPage );
            }
            sqrl_free( page, sizeof( struct S4Page ) );
            page = NULL;
        }
        return page;
    }

    static bool find_block( struct S4Page *page, struct S4Pointer *pointer, uint16_t blockType ) {
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

    static bool allocate_block( struct S4Page *page, struct S4Pointer *pointer, uint16_t blockType, uint16_t blockLength ) {
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

    static bool sqrl_storage_block_remove( struct S4Page *page, uint16_t blockType ) {
        if( !page ) return false;
        struct S4Pointer pointer;
        if( find_block( page, &pointer, blockType ) ) {
            SQRL_STORAGE_READ_WRITE( pointer.page );
            pointer.index->active = 0;
            sqrl_memzero( pointer.page->blocks + pointer.index->offset, pointer.index->blockLength );
            SQRL_STORAGE_LOCK( pointer.page );
            return true;
        }
        return false;
    }

    static bool sqrl_storage_block_put( struct S4Page *page, SqrlBlock *block ) {
        if( !page || !block ) return false;
        struct S4Pointer pointer;
        SqrlString *data = block->getData( NULL );
        if( !data ) {
            return false;
        }
        if( find_block( page, &pointer, block->getBlockType() ) ) {
            SQRL_STORAGE_READ_ONLY( pointer.page );
            if( pointer.index->blockLength <= block->getBlockLength() ) {
                SQRL_STORAGE_READ_WRITE( pointer.page );
                if( data->length() > 0 ) {
                    memcpy( &pointer.page->blocks[pointer.index->offset],
                        data->cdata(), data->length() );
                    if( pointer.index->blockLength < data->length() ) {
                        memset( (&pointer.page->blocks[pointer.index->offset]) + data->length(),
                            0, data->length() - pointer.index->blockLength );
                    }
                }
                pointer.index->blockLength = block->getBlockLength();
                SQRL_STORAGE_LOCK( pointer.page );
                delete data;
                return true;
            }
            SQRL_STORAGE_LOCK( pointer.page );
            sqrl_storage_block_remove( page, block->getBlockType() );
        }
        if( allocate_block( page, &pointer, block->getBlockType(), block->getBlockLength() ) ) {
            SQRL_STORAGE_READ_WRITE( pointer.page );
            if( data->length() > 0 ) {
                memcpy( &pointer.page->blocks[pointer.index->offset],
                    data->cdata(), data->length() );
            }
            SQRL_STORAGE_LOCK( pointer.page );
            delete data;
            return true;
        }
        delete data;
        return false;
    }

    static bool sqrl_storage_block_exists( struct S4Page *page, uint16_t blockType ) {
        if( !page ) return false;
        struct S4Pointer pointer;
        if( find_block( page, &pointer, blockType ) ) {
            return true;
        }
        return false;
    }

    static bool sqrl_storage_block_get( struct S4Page *page, SqrlBlock *block, uint16_t blockType ) {
        if( !page || !block ) return false;
        block->clear();
        struct S4Pointer pointer;
        if( find_block( page, &pointer, blockType ) ) {
            SQRL_STORAGE_READ_ONLY( pointer.page );
            if( block->init( pointer.index->blockType, pointer.index->blockLength ) ) {
                block->write( pointer.page->blocks + pointer.index->offset, block->getBlockLength() );
                SQRL_STORAGE_LOCK( pointer.page );
                return true;
            }
            SQRL_STORAGE_LOCK( pointer.page );
            return false;
        }
        return false;
    }

    static bool sqrl_storage_load_from_buffer( struct S4Page *page, SqrlString *buffer ) {
        bool retVal = true;
        SqrlBlock *block = NULL;

        if( buffer->compare( 0, 8, "sqrldata" ) == 0 ) {
            buffer->erase( 0, 8 );
        } else {
            if( buffer->compare( 0, 8, "SQRLDATA" ) == 0 ) {
                SqrlString buf( buffer );
                buf.erase( 0, 8 );
                SqrlBase64().decode( buffer, &buf );
            }
        }

        const uint8_t * cur = buffer->cdata();
        const uint8_t * end = buffer->cdend();
        block = SqrlBlock::create();

        while( cur + 4 < end ) {
            uint16_t bl = (uint16_t)cur[0] | (((uint16_t)cur[1]) << 8);
            uint16_t bt = (uint16_t)cur[2] | (((uint16_t)cur[3]) << 8);
            block->init( bt, bl );
            if( cur + bl > end ) {
                printf( "Invalid block Length\n" );
                goto ERR;
            }
            block->write( (uint8_t*)cur, bl );
            if( sqrl_storage_block_put( page, block ) ) {
                cur += bl;
                continue;
            }
            goto ERR;
        }
        goto DONE;

    ERR:
        retVal = false;

    DONE:
        block->release();
        return retVal;
    }

    static bool sqrl_storage_load_from_file( struct S4Page *page, const char *filename ) {
#ifdef ARDUINO
        return false;
#else
        char tmp[1024];
        size_t bytesRead;
        bool retVal;
        FILE *fp = fopen( filename, "rb" );
        if( !fp ) return false;

        SqrlString buf = SqrlString();

        while( !feof( fp ) ) {
            bytesRead = fread( tmp, 1, 1024, fp );
            if( bytesRead > 0 ) {
                buf.append( tmp, bytesRead );
            }
        }
        fclose( fp );

        retVal = sqrl_storage_load_from_buffer( page, &buf );
        return retVal;
#endif
    }

    static SqrlString *sqrl_storage_save_to_string(
        struct S4Page *page,
        Sqrl_Export etype,
        Sqrl_Encoding encoding ) {
        SqrlString tmp = SqrlString();
        SqrlString *buf = new SqrlString();
        int i;

        if( etype == SQRL_EXPORT_RESCUE ) {
            SqrlBlock *block = SqrlBlock::create();
            if( sqrl_storage_block_get( page, block, SQRL_BLOCK_RESCUE ) ) {
                block->getData( &tmp );
            }
            if( sqrl_storage_block_get( page, block, SQRL_BLOCK_PREVIOUS ) ) {
                block->getData( &tmp, true );
            }
            block->release();
        } else {
            struct S4Page *nextPage;
            while( page ) {
                SQRL_STORAGE_READ_ONLY( page );
                for( i = 0; i < BLOCKS_PER_PAGE; i++ ) {
                    if( page->index[i].active ) {
                        tmp.append( (char*)(page->blocks + page->index[i].offset), page->index[i].blockLength );
                    }
                }
                nextPage = page->nextPage;
                SQRL_STORAGE_LOCK( page );
                page = nextPage;
            }
        }

        if( encoding == SQRL_ENCODING_BASE64 ) {
            buf->append( "SQRLDATA" );
            SqrlBase64().encode( buf, &tmp, true );
        } else {
            buf->append( "sqrldata" );
            buf->append( &tmp );
        }
        return buf;
    }

    static int sqrl_storage_save_to_file( struct S4Page *page, const char *filename, Sqrl_Export etype, Sqrl_Encoding encoding ) {
#ifdef ARDUINO
        return 0;
#else
        int retVal;
        SqrlString *buf = sqrl_storage_save_to_string( page, etype, encoding );
        FILE *fp = fopen( filename, "wb" );
        if( !fp ) {
            delete buf;
            return -1;
        }
        retVal = (int)fwrite( buf->cdata(), 1, buf->length(), fp );
        fclose( fp );
        if( retVal != (int)buf->length() ) retVal = -1;
        delete buf;
        return retVal;
#endif
    }

    static void sqrl_storage_unique_id( struct S4Page *page, char *unique_id ) {
        if( !unique_id ) return;
        SqrlBlock *block = SqrlBlock::create();
        if( !page ) goto ERR;
        if( sqrl_storage_block_exists( page, SQRL_BLOCK_RESCUE &&
            sqrl_storage_block_get( page, block, SQRL_BLOCK_RESCUE ) ) ) {
            if( block->getBlockLength() == 73 ) {
                SqrlString buf;
                SqrlString tstr;
                uint8_t tmp[SQRL_KEY_SIZE];
                block->seek( 25 );
                block->read( tmp, SQRL_KEY_SIZE );
                tstr.append( (char*)tmp, SQRL_KEY_SIZE );
                SqrlBase64().encode( &buf, &tstr );
                memcpy( unique_id, buf.cdata(), buf.length() );
                return;
            }
        }

    ERR:
        memset( unique_id, 0, SQRL_UNIQUE_ID_LENGTH + 1 );
    }


    SqrlStorage *SqrlStorage::empty() {
        SqrlStorage *storage = (SqrlStorage*)malloc( sizeof( SqrlStorage ) );
        new (storage) SqrlStorage();
        return storage;
    }

    SqrlStorage *SqrlStorage::from( SqrlString *buffer ) {
        SqrlStorage *storage = (SqrlStorage*)malloc( sizeof( SqrlStorage ) );
        new (storage) SqrlStorage();
        if( storage->load( buffer ) ) {
            return storage;
        }
        storage->~SqrlStorage();
        free( storage );
        return NULL;
    }

    SqrlStorage *SqrlStorage::from( SqrlUri *uri ) {
        SqrlStorage *storage = (SqrlStorage*)malloc( sizeof( SqrlStorage ) );
        new (storage) SqrlStorage();
        if( storage->load( uri ) ) {
            return storage;
        }
        storage->~SqrlStorage();
        return NULL;
    }

    SqrlStorage::SqrlStorage() {
        this->data = sqrl_page_create();
    }

    SqrlStorage *SqrlStorage::release() {
        this->~SqrlStorage();
        return NULL;
    }

    SqrlStorage::~SqrlStorage() {
        SQRL_CAST_PAGE( page, this->data );
        page = sqrl_page_destroy( page );
        free( this );
    }

    bool SqrlStorage::hasBlock( uint16_t blockType ) {
        SQRL_CAST_PAGE( page, this->data );
        return sqrl_storage_block_exists( page, blockType );
    }

    bool SqrlStorage::getBlock( SqrlBlock *block, uint16_t blockType ) {
        SQRL_CAST_PAGE( page, this->data );
        return sqrl_storage_block_get( page, block, blockType );
    }

    bool SqrlStorage::putBlock( SqrlBlock *block ) {
        SQRL_CAST_PAGE( page, this->data );
        return sqrl_storage_block_put( page, block );
    }

    bool SqrlStorage::removeBlock( uint16_t blockType ) {
        SQRL_CAST_PAGE( page, this->data );
        return sqrl_storage_block_remove( page, blockType );
    }

    bool SqrlStorage::load( SqrlString *buffer ) {
        SQRL_CAST_PAGE( page, this->data );
        return sqrl_storage_load_from_buffer( page, buffer );
    }

    bool SqrlStorage::load( SqrlUri *uri ) {
        SQRL_CAST_PAGE( page, this->data );
        if( uri->getScheme() != SQRL_SCHEME_FILE ) return false;
        SqrlString fn = SqrlString();
        uri->getChallenge( &fn );
        bool ret = sqrl_storage_load_from_file( page, fn.string() );
        return ret;
    }

    SqrlString *SqrlStorage::save( Sqrl_Export etype, Sqrl_Encoding encoding ) {
        SQRL_CAST_PAGE( page, this->data );
        return sqrl_storage_save_to_string( page, etype, encoding );
    }

    bool SqrlStorage::save( SqrlUri *uri, Sqrl_Export etype, Sqrl_Encoding encoding ) {
        SQRL_CAST_PAGE( page, this->data );
        if( uri->getScheme() != SQRL_SCHEME_FILE ) return false;
        SqrlString fn = SqrlString();
        uri->getChallenge( &fn );
        int ret = sqrl_storage_save_to_file( page, fn.string(), etype, encoding );
        return ret > 0;
    }

    void SqrlStorage::getUniqueId( char *unique_id ) {
        SQRL_CAST_PAGE( page, this->data );
        return sqrl_storage_unique_id( page, unique_id );
    }
}
