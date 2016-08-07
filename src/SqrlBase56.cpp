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

//static char BASE56_TABLE[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
//static char BASE56_TABLE[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

SqrlBase56::SqrlBase56() {
	this->alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
}

SqrlString *SqrlBase56::encode( SqrlString *dest, const SqrlString *src, bool append ) {
	if( !src ) return NULL;
	if( !dest ) {
		dest = new SqrlString();
	} 
	if( ! append ) {
		dest->clear();
	}

	SqrlBigInt s( src->length() );
	SqrlString d( src->length() );
	s.append( (char)0xFF, src->length() );
	size_t cnt = 0;
	while( s.length() != 0 ) {
		s.divideBy( 56 );
		cnt++;
	}
	s.append( src );
	s.reverse();
	uint8_t rem = 0;

	while( cnt > 0 ) {
		rem = s.divideBy( 56 );
		d.push_back( this->alphabet[rem] );
		cnt--;
	}
	d.reverse();
	dest->append( &d );
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
	SqrlBigInt num = SqrlBigInt();
	const char *ch;
	uint8_t dp;

	for( const uint8_t *it = src->cdata(); it != src->cdend(); it++ ) {
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

