#include "sqrl_internal.h"
#include "SqrlEncoder.h"
#include "SqrlString.h"
#include "SqrlBigInt.h"

namespace libsqrl
{
	SqrlEncoder::SqrlEncoder() : SqrlEncoder( "0123456789abcdef" ) {}

	SqrlEncoder::SqrlEncoder( const char * alphabet ) {
		this->alphabet = alphabet;
		this->reverseMath = true;
	}

	SqrlString *SqrlEncoder::encode( SqrlString *dest, const SqrlString *src, bool append ) {
		if( !src ) return NULL;
		if( !dest ) {
			dest = new SqrlString();
		}
		if( !append ) {
			dest->clear();
		}
		if( src->length() == 0 ) return dest;

		int base = (int)strlen( this->alphabet );
		int cpb = ceil( 8.0 / log2(base) );
		int cnt = src->length() * cpb;
		uint8_t rem;
		SqrlBigInt s( src );

		dest->reserve( dest->length() + cnt );
		if( this->reverseMath )	s.reverse();

		do {
			rem = s.divideBy( base );
			dest->push_back( this->alphabet[(rem == base ? 0 : rem)] );
		} while( s.length() );

		cnt -= (int)dest->length();
		cnt = (cnt / cpb) * cpb;
		if( cnt ) dest->append( this->alphabet[0], cnt );

		if( this->reverseMath ) dest->reverse();
		return dest;
	}

	SqrlString *SqrlEncoder::decode( SqrlString *dest, const SqrlString *src, bool append ) {
		if( !src ) return NULL;
		if( !dest ) {
			dest = new SqrlString();
		}
		if( !append ) {
			dest->clear();
		}
		if( src->length() == 0 ) return dest;
		int base = (int)strlen( this->alphabet );

		SqrlString s = SqrlString( src );
		SqrlBigInt num = SqrlBigInt();
		const char *ch;
		uint8_t dp;
		size_t leadingZeros = 0;
		size_t cpb = (size_t)ceil( 8.0 / log2(base) );
		bool leading = true;
		const uint8_t *it = s.cdata();
		const uint8_t *end = s.cdend();
		while( it[0] == this->alphabet[0] && it != end ) {
			leadingZeros++;
			it++;
		}
		leadingZeros = leadingZeros / cpb;
		while( it != end ) {
			ch = strchr( this->alphabet, *it );
			if( ch ) {
				dp = (uint8_t)(ch - this->alphabet);
				num.multiplyBy( base );
				num.add( dp );
			}
			it++;
		}

		if( leadingZeros ) {
			dest->append( (char)0, leadingZeros );
		}
		dest->append( &num );
		return dest;
	}

}
