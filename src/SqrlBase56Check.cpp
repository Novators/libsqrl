/** \file SqrlBase56Check.cpp
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlBase56Check.h"
#include "SqrlBase56.h"
#include "SqrlBigInt.h"

namespace libsqrl
{
	SqrlBase56Check::SqrlBase56Check() : SqrlBase56() {}

	SqrlString *SqrlBase56Check::encode( SqrlString *dest, const SqrlString *src, bool append ) {
		if( !src || src->length() == 0 ) return NULL;
		if( !dest ) {
			dest = new SqrlString();
		}
		if( !append ) {
			dest->clear();
		}
		SqrlString encoded = SqrlString();
		if( !this->SqrlBase56::encode( &encoded, src ) ) {
			return NULL;
		}

		uint8_t lineCount = 0;
		SqrlString line = SqrlString( 20 );
		SqrlBigInt sha = SqrlBigInt( 32 );
		while( encoded.substring( &line, lineCount * 19, 19 ) ) {
			line.append( lineCount, 1 );
			sha.clear();
			sha.append( (char)0, 32 );
			crypto_hash_sha256( (unsigned char*)sha.data(), (unsigned char*)line.data(), line.length() );
			uint8_t rem = sha.divideBy( 56 );
			line.popc_back();
			line.append( this->alphabet[rem], 1 );
			dest->append( &line );
			lineCount++;
		}
		return dest;
	}

	SqrlString *SqrlBase56Check::decode( SqrlString *dest, const SqrlString *src, bool append ) {
		if( !src || src->length() == 0 ) return NULL;
		SqrlString toDecode = SqrlString( src->length() );

		bool isError = false;
		uint8_t lineCount = 0;
		SqrlString line = SqrlString( 20 );
		SqrlBigInt sha = SqrlBigInt( 32 );
		while( src->substring( &line, lineCount * 20, 20 ) ) {
			char checkChar = line.popc_back();
			line.append( lineCount, 1 );
			sha.clear();
			sha.append( (char)0, 32 );
			crypto_hash_sha256( (unsigned char*)sha.data(), (unsigned char*)line.data(), line.length() );
			uint8_t rem = sha.divideBy( 56 );
			if( checkChar != this->alphabet[rem] ) {
				isError = true;
				break;
			}
			line.popc_back();
			toDecode.append( &line );
			lineCount++;
		}
		if( isError ) {
			printf( "Failed at line %d\n", lineCount );
			return NULL;
		}

		bool didAlloc = false;
		if( !dest ) {
			dest = new SqrlString();
			didAlloc = true;
		}

		if( !this->SqrlBase56::decode( dest, &toDecode, append ) ) {
			delete dest;
			return NULL;
		}

		return dest;
	}

}
