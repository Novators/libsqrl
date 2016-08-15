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
    SqrlStorage::SqrlStorage() : data( SqrlDeque<SqrlBlock*>() ) {}
    SqrlStorage::SqrlStorage( SqrlString *buffer ) : SqrlStorage() {
        this->load( buffer );
    }
    SqrlStorage::SqrlStorage( SqrlUri *uri ) : SqrlStorage() {
        this->load( uri );
    }
    SqrlStorage::~SqrlStorage() {
        SqrlBlock *block;
        while( block = this->data.pop() ) {
            delete block;
        }
    }

    bool SqrlStorage::hasBlock( uint16_t blockType ) {
        SqrlBlock *block;
        size_t cnt = 0;
        do {
            block = this->data.peek( cnt++ );
            if( block ) {
                if( block->getBlockType() == blockType ) {
                    return true;
                }
            } else {
                break;
            }
        } while( 1 );
        return false;
    }

    bool SqrlStorage::getBlock( SqrlBlock *block, uint16_t blockType ) {
        if( !block ) return false;
        SqrlBlock *b;
        size_t cnt = 0;
        do {
            b = this->data.peek( cnt++ );
            if( b ) {
                if( b->getBlockType() == blockType ) {
                    block->clear();
                    block->append( b );
                    return true;
                }
            } else {
                break;
            }
        } while( 1 );
        return false;
    }

    bool SqrlStorage::putBlock( SqrlBlock *block ) {
        if( !block ) return false;
        SqrlBlock *b = new SqrlBlock( block );
        this->removeBlock( block->getBlockType() );
        this->data.push_back( b );
        return true;
    }

    bool SqrlStorage::removeBlock( uint16_t blockType ) {
        SqrlBlock *b;
        size_t cnt = 0;
        do {
            b = this->data.peek( cnt++ );
            if( b ) {
                if( b->getBlockType() == blockType ) {
                    this->data.erase( b );
                    return true;
                }
            }
        } while( b );
        return false;
    }

    void SqrlStorage::clear() {
        SqrlBlock *b = this->data.pop();
        while( b ) {
            delete b;
            b = this->data.pop();
        }
    }

    bool SqrlStorage::load( SqrlString *buffer ) {
        this->clear();
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

        while( cur + 4 < end ) {
            SqrlBlock block = SqrlBlock( cur );
            if( cur + block.length() > end ) {
                return false;
            }
            if( this->putBlock( &block ) ) {
                cur += block.length();
                continue;
            }
            return false;
        }
        return true;
    }

    bool SqrlStorage::load( SqrlUri *uri ) {
#ifdef ARDUINO
        return false;
#else
        if( !uri || uri->getScheme() != SQRL_SCHEME_FILE ) return false;
        SqrlString fn = SqrlString();
        uri->getChallenge( &fn );
        char tmp[1024];
        size_t bytesRead;
        FILE *fp = fopen( fn.cstring(), "rb" );
        if( !fp ) return false;

        SqrlString buf = SqrlString();

        while( !feof( fp ) ) {
            bytesRead = fread( tmp, 1, 1024, fp );
            if( bytesRead > 0 ) {
                buf.append( tmp, bytesRead );
            }
        }
        fclose( fp );
        return this->load( &buf );
#endif
    }

    SqrlString *SqrlStorage::save( Sqrl_Export etype, Sqrl_Encoding encoding ) {
        SqrlString tmp = SqrlString();
        SqrlString *buf = new SqrlString();

        if( etype == SQRL_EXPORT_RESCUE ) {
            SqrlBlock block = SqrlBlock();
            if( this->getBlock( &block, SQRL_BLOCK_RESCUE ) ) {
                block.getData( &tmp );
            }
            if( this->getBlock( &block, SQRL_BLOCK_PREVIOUS ) ) {
                block.getData( &tmp, true );
            }
        } else {
            SqrlBlock *b;
            size_t cnt = 0;
            do {
                b = this->data.peek( cnt++ );
                if( b ) {
                    tmp.append( b );
                } else {
                    break;
                }
            } while( 1 );
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

    bool SqrlStorage::save( SqrlUri *uri, Sqrl_Export etype, Sqrl_Encoding encoding ) {
#ifdef ARDUINO
        return 0;
#else
        if( !uri || uri->getScheme() != SQRL_SCHEME_FILE ) return false;
        SqrlString fn = SqrlString();
        uri->getChallenge( &fn );
        int retVal;
        SqrlString *buf = this->save( etype, encoding );
        FILE *fp = fopen( fn.string(), "wb" );
        if( !fp ) {
            delete buf;
            return false;
        }
        retVal = (int)fwrite( buf->cdata(), 1, buf->length(), fp );
        fclose( fp );
        if( retVal != (int)buf->length() ) retVal = -1;
        delete buf;
        return retVal != -1;
#endif
    }

    void SqrlStorage::getUniqueId( SqrlString *unique_id ) {
        if( !unique_id ) return;
        SqrlBlock block = SqrlBlock();
        if( this->getBlock( &block, SQRL_BLOCK_RESCUE ) ) {
            if( block.getBlockLength() == 73 ) {
                SqrlString tstr;
                block.substring( &tstr, 25, SQRL_KEY_SIZE );
                SqrlBase64().encode( unique_id, &tstr );
                return;
            }
        }
        unique_id->clear();
    }

}
