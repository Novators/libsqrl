/** \file SqrlBase64.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlBase64.h"

namespace libsqrl
{
	SqrlBase64::SqrlBase64() : SqrlEncoder( "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" ) {}
	
	SqrlString *SqrlBase64::encode( SqrlString *dest, const SqrlString *src, bool append ) {
		if( !src || src->length() == 0 ) return NULL;
		size_t src_len = src->length();
		if( !dest ) dest = new SqrlString();
		if( append ) {
			dest->reserve( dest->length() + (size_t)(src_len * 4.0 / 3.0) );
		} else {
			dest->clear();
			dest->reserve( (size_t)(src_len * 4.0 / 3.0) );
		}
		int i = 16;
		uint32_t tmp = 0;
		char str[4];

		const uint8_t *it = src->cdata();
		const uint8_t *end = src->cdend();
		while( 1 ) {
			tmp |= (*it++ & 0xFF) << i;
			if( i == 0 || it == end ) {
				str[0] = this->alphabet[(tmp >> 18) & 0x3F];
				str[1] = this->alphabet[(tmp >> 12) & 0x3F];
				str[2] = this->alphabet[(tmp >> 6) & 0x3F];
				str[3] = this->alphabet[tmp & 0x3F];
				dest->append( (uint8_t*)str, 4 );
				if( it == end ) break;
				tmp = 0;
				i = 16;
			} else {
				i -= 8;
			}
		}
		i = 3 - (src_len % 3);
		if( i != 3 ) {
			dest->erase( dest->length() - i, dest->length() );
		}
		return dest;
	}

	SqrlString *SqrlBase64::decode( SqrlString *dest, const SqrlString *src, bool append ) {
		if( !src || src->length() == 0 ) return NULL;
		size_t input_length = src->length();
		if( !dest ) dest = new SqrlString();
		if( append ) {
			dest->reserve( dest->length() + (size_t)(input_length * 3.0 / 4.0) );
		} else {
			dest->clear();
			dest->reserve( (size_t)(input_length * 3.0 / 4.0) );
		}
		int shift = 18, charCount = 0;
		uint32_t tmp = 0;
		char str[3];
		const char *cptr;

		const char *it = src->cstring();
		const char *end = src->cstrend();
		while( 1 ) {
			cptr = strchr( this->alphabet, (it++)[0] );
			if( cptr ) {
				tmp |= ((cptr - this->alphabet) << shift);
				charCount++;
				if( !shift || it == end ) {
					str[0] = (char)((tmp >> 16) & 0xFF);
					str[1] = (char)((tmp >> 8) & 0xFF);
					str[2] = (char)(tmp & 0xFF);
					dest->append( (uint8_t*)str, 3 );
					if( it == end ) break;
					shift = 18;
					tmp = 0;
				} else {
					shift -= 6;
				}
			}
		}
		charCount = 4 - (charCount % 4);
		if( charCount != 4 ) {
			dest->erase( dest->length() - charCount, dest->length() );
		}
		return dest;
	}
}
