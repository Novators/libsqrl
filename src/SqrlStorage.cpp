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
#include "SqrlBase56Check.h"
#include <new>

namespace libsqrl
{
    /// <summary>Default constructor.</summary>
    SqrlStorage::SqrlStorage() : data( SqrlDeque<SqrlBlock*>() ) {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.  Creates a SqrlStorage object with the contents of an S4 formatted buffer.</summary>
    ///
    /// <remarks>The supplied buffer may be modified.</remarks>
    /// 
    /// <param name="buffer">[in] The SqrlString to load data from.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlStorage::SqrlStorage( SqrlString *buffer ) : SqrlStorage() {
        this->load( buffer );
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.  Creates a SqrlStorage object with the contents of a file.</summary>
    ///
    /// <param name="uri">[in] The SqrlUri containing the file's path and name.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    SqrlStorage::SqrlStorage( SqrlUri *uri ) : SqrlStorage() {
        this->load( uri );
    }
    SqrlStorage::~SqrlStorage() {
        SqrlBlock *block;
        while( (block = this->data.pop()) ) {
            delete block;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Query if this SqrlStorage has a block of type blockType.</summary>
    ///
    /// <param name="blockType">Type of the block.</param>
    ///
    /// <returns>true if this SqrlStorage contains a block of type blockType, false if not.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets a block.</summary>
    ///
    /// <param name="block">    [out] A SqrlBlock object to write the block's data to.</param>
    /// <param name="blockType">Type of the block.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds a SqrlBlock to this SqrlStorage.</summary>
    ///
    /// <param name="block">[in] If non-null, the block.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlStorage::putBlock( SqrlBlock *block ) {
        if( !block ) return false;
        SqrlBlock *b = new SqrlBlock( block );
        this->removeBlock( block->getBlockType() );
        this->data.push_back( b );
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the block of type blockType from this SqrlStorage, if it exists.</summary>
    ///
    /// <param name="blockType">Type of the block.</param>
    ///
    /// <returns>true if a block was removed, false if not.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    /// <summary>Removes all SqrlBlocks stored in the SqrlStorage.</summary>
    void SqrlStorage::clear() {
        SqrlBlock *b = this->data.pop();
        while( b ) {
            delete b;
            b = this->data.pop();
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears this SqrlStorage and reloads data from the given buffer.</summary>
    ///
    /// <param name="buffer">[in] The buffer to load from.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool SqrlStorage::load( SqrlString *buffer ) {
        this->clear();
        if( buffer->compare( 0, 8, "sqrldata" ) == 0 ) {
            buffer->erase( 0, 8 );
        } else {
			SqrlString buf( buffer );
            if( buffer->compare( 0, 8, "SQRLDATA" ) == 0 ) {
                buf.erase( 0, 8 );
                SqrlBase64().decode( buffer, &buf );
			} else {
				SqrlBase56Check b56;
				if( b56.validate( buffer, NULL ) ) {
					b56.decode( buffer, &buf );
				} else {
					return false;
				}
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears this SqrlStorage and reloads data from the given file.</summary>
    ///
    /// <param name="uri">[in] The SqrlUri of the file to load from.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Saves the contents of this SqrlStorage into a new SqrlString, with S4 formatting.</summary>
    ///
    /// <param name="etype">   The type of export</param>
    /// <param name="encoding">The encoding.</param>
    ///
    /// <returns>null if it fails, else a pointer to a SqrlString.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Saves the contents of this SqrlStorage to a file, with S4 formatting.</summary>
    ///
    /// <param name="uri">     [in] The SqrlUri of the file to save to.</param>
    /// <param name="etype">   The type of export</param>
    /// <param name="encoding">The encoding.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
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
            if( block.length() == 73 ) {
                SqrlString tstr;
                block.substring( &tstr, 25, SQRL_KEY_SIZE );
                SqrlBase64().encode( unique_id, &tstr );
                return;
            }
        }
        unique_id->clear();
    }

}
