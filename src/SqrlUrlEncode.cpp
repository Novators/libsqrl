/** \file SqrlUrlEncode.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlUrlEncode.h"

using libsqrl::SqrlString;
using libsqrl::SqrlUrlEncode;

libsqrl::SqrlUrlEncode::SqrlUrlEncode() : SqrlEncoder( "0123456789ABCDEF" ) {}

SqrlString * libsqrl::SqrlUrlEncode::encode( SqrlString * dest, const SqrlString * src, bool append ) {
	if( !dest ) {
		dest = new SqrlString();
	} else {
		if( !append ) dest->clear();
	}
	char str[3];
	str[0] = '%';
	
	const char *it = src->cstring();
	const char *end = src->cstrend();

	while( it != end ) {
		if( it[0] == ' ' ) {
			dest->push_back( '+' );
		} else if( (it[0] >= '0' && it[0] <= '9') ||
			(it[0] >= 'A' && it[0] <= 'Z') ||
			(it[0] >= 'a' && it[0] <= 'z') ) {
			dest->append( it[0], 1 );
		} else {
			str[1] = this->alphabet[it[0] >> 4];
			str[2] = this->alphabet[it[0] & 0x0F];
			dest->append( str, 3 );
		}
		it++;
	}
	return dest;
}

SqrlString * libsqrl::SqrlUrlEncode::decode( SqrlString * dest, const SqrlString * src, bool append ) {
	if( !dest ) {
		dest = new SqrlString();
	} else {
		if( !append ) dest->clear();
	}
	char dc;
	int i;
	char tmp = 0;

	const char *it = src->cstring();
	const char *end = src->cstrend();

	while( it != end ) {
		if( it[0] == '+' ) {
			dest->push_back( ' ' );
		} else if( it[0] == '%' && (it + 2) < end ) {
			for( i = 1; i <= 2; i++ ) {
				dc = it[i];
				if( dc >= '0' && dc <= '9' ) {
					dc -= 48;
				} else if( dc >= 'a' && dc <= 'f' ) {
					dc -= 87;
				} else if( dc >= 'A' && dc <= 'F' ) {
					dc -= 55;
				} else {
					dc = (char)255;
				}
				if( dc < 16 ) {
					if( i == 1 ) {
						tmp = dc << 4;
					} else {
						tmp |= dc;
					}
				}
			}
			dest->push_back( tmp );
			it += 2;
		} else {
			dest->push_back( it[0] );
		}
		it++;
	}
	return dest;
}

