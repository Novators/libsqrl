/** \file SqrlBigInt.h
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/
#ifndef SQRLBIGINT_H
#define SQRLBIGINT_H

#include "sqrl.h"
#include "SqrlString.h"

class SqrlBigInt : public SqrlString
{
private:
	void stripLeadingZeros() {
		uint8_t *it = this->data();
		uint8_t *end = this->dend();
		size_t cnt = 0;
		while( it != end && *it == 0 ) {
			cnt++;
			it++;
		}
		if( cnt ) {
			this->erase( 0, cnt );
		}
	}

public:
	SqrlBigInt() : SqrlString() {};
	SqrlBigInt( const SqrlString *in ) : SqrlString( in ) {};
	SqrlBigInt( size_t len ) : SqrlString( len ) {};

	void add( uint8_t operand ) {
		if( this->length() == 0 ) {
			this->append( (char)operand, 1 );
			return;
		}
		uint16_t carry = 0;
		uint16_t t = 0;
		uint8_t *it = this->dend() - 1;
		uint8_t *end = this->data();

		t = *it + operand;
		*it = (uint8_t)t;
		carry = t >> 8;
		it--;
		while( it >= end && carry ) {
			t = carry + *it;
			*it = (uint8_t)t;
			carry = t >> 8;
			it--;
		}
		if( carry ) {
			this->insert( 0, (uint8_t)carry );
		}
	}

	void multiplyBy( uint8_t multiplicand ) {
		if( this->length() == 0 ) {
			return;
		}
		SqrlString result( this->length() + 1 );
		uint16_t carry = 0;
		uint16_t t;
		while( this->length() ) {
			t = (uint16_t)this->popb_back() * multiplicand + carry;
			result.push_back( (uint8_t)(t & 0xFF) );
			carry = t >> 8;
		}
		if( carry ) {
			result.push_back( (uint8_t)carry );
		}
		result.reverse();
		this->append( &result );
	}

	uint8_t divideBy( uint8_t divisor ) {
		if( divisor == 0 ) {
			return 0;
		}
		// TODO: Optimize BigInt division
		this->reverse();
		uint8_t *it = this->data();
		uint8_t *end = this->dend();
		uint16_t rem = 0;
		uint16_t t = 0;
		while( it != end ) {
			t = rem << 8;
			t += *it;
			rem = t % divisor;
			t = t / divisor;
			*it = (uint8_t)t;
			it++;
		}
		this->stripLeadingZeros();
		this->reverse();
		return (uint8_t)rem;
	}

};

#endif // SQRLBIGINT_H

