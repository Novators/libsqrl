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

SqrlString *SqrlBase56::encode( SqrlString *dest, const SqrlString *src, bool append ) {
	if( !src ) return NULL;
	if( !dest ) {
		dest = new SqrlString();
	} 
	if( ! append ) {
		dest->clear();
	}

	SqrlBigInt s( src->length() );
	s.append( (char)0xFF, src->length() );
	size_t cnt = 0;
	while( s.length() != 0 ) {
		s.divideBy( 56 );
		cnt++;
	}
	s.append( src );
	uint8_t rem = 0;

	while( cnt > 0 ) {
		rem = s.divideBy( 56 );
		dest->push_back( this->alphabet[rem] );
		cnt--;
	}
	return dest;
}

SqrlString *SqrlBase56::decode( SqrlString *dest, const SqrlString *src, bool append ) {
	if( !src ) return NULL;
	if( !dest ) {
		dest = new SqrlString();
	}
	if( !append ) {
		dest->clear();
	}
	SqrlString s = SqrlString( src );
	s.reverse();
	SqrlBigInt num = SqrlBigInt();
	const char *ch;
	uint8_t dp;

	for( const uint8_t *it = s.cdata(); it != s.cdend(); it++ ) {
		ch = strchr( this->alphabet, *it );
		if( ch ) {
			dp = (uint8_t)(ch - this->alphabet);
			num.multiplyBy( 56 );
			num.add( dp );
		}
	}
	num.reverse();
	dest->append( &num );
	return dest;
}

