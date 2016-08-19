/** \file SqrlBase56.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlBase56.h"
#include "SqrlBigInt.h"

namespace libsqrl
{
	SqrlBase56::SqrlBase56() : SqrlEncoder( "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz" ) {
		this->reverseMath = false;
	}
	/*
	SqrlString *SqrlBase56::encode( SqrlString *dest, const SqrlString *src, bool append ) {
		if( !src ) return NULL;
		if( !dest ) {
			dest = new SqrlString();
		}
		if( !append ) {
			dest->clear();
		}
		if( src->length() == 0 ) return dest;

		int base = (int)strlen( this->alphabet );
		double charsPerByte = 8.0 / log2( base );
		size_t cnt;
		SqrlBigInt s( src );

		do {
			dest->push_back( this->alphabet[(s.divideBy( base )) % base] );
		} while( s.length() );

		cnt = ceil(src->length() * charsPerByte) - dest->length();
		if( cnt ) {
			dest->append( this->alphabet[0], cnt );
		}

		return dest;
	}

	SqrlString *SqrlBase56::decode( SqrlString *dest, const SqrlString *src, bool append ) {
		if( !src || src->length() == 0 ) return NULL;
		if( !dest ) {
			dest = new SqrlString();
		}
		if( !append ) {
			dest->clear();
		}
		int base = (int)strlen( this->alphabet );
		SqrlString s = SqrlString( src );
		s.reverse();
		SqrlBigInt num = SqrlBigInt();
		const char *ch;
		uint8_t dp;

		for( const uint8_t *it = s.cdata(); it != s.cdend(); it++ ) {
			ch = strchr( this->alphabet, *it );
			if( ch ) {
				dp = (uint8_t)(ch - this->alphabet);
				num.multiplyBy( base );
				num.add( dp );
			}
		}
		num.reverse();
		dest->append( &num );
		return dest;
	}
	*/
}