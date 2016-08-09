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

namespace libsqrl
{
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>A partial implementation of big integer arithmetic, using SqrlString as the data.
	/// 		 This is SQRL specific, in that it only supports single byte operands, and the divide
	/// 		 operation works in reverse.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class SqrlBigInt : public SqrlString
	{
	private:
		/// <summary>Removes trailing zeros.</summary>
		void stripTrailingZeros() {
			while( this->length() ) {
				char c = this->popc_back(); // Remove the last byte from buffer.
				if( c != 0 ) {              // If it is not zero,
					this->push_back( c );   // put it back,
					break;                  // and end.
				}                           // Otherwise, discard it and move to previous byte in buffer.
			}
		}

	public:
		SqrlBigInt() : SqrlString() {};
		SqrlBigInt( const SqrlString *in ) : SqrlString( in ) {};
		SqrlBigInt( size_t len ) : SqrlString( len ) {};

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Adds a single byte to the string.</summary>
		///
		/// <param name="operand">The byte to add.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void add( uint8_t operand ) {
			if( this->length() == 0 ) {            // If the buffer is empty,
				this->append( (char)operand, 1 );  // just store the operand.
				return;
			}
			uint16_t carry = 0;                    // Stores the carry byte.
			uint16_t t = operand;                  // Temporary variable, initialized with operand.
			uint8_t *it = this->dend();            // Start *after* the last byte in the buffer,
			uint8_t *end = this->data();           // and end when the first byte has been processed.

			do {
				it--;                              // Move to the previous byte in buffer.
				t += *it + carry;                  // Add the byte and any carry value.
				*it = (uint8_t)t;                  // Store result byte,
				carry = t >> 8;                    // and carry any overflow to next operation.
				t = 0;                             // Reset temporary variable for next operation.
			} while( it != end );                  // Have we processed the first byte in buffer?

			if( carry ) {                          // If there is still a carry,
				this->insert( 0, (uint8_t)carry ); // Store it as a new byte at beginning of buffer.
			}
		}

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Multiplies the string by a single byte.</summary>
		///
		/// <param name="multiplicand">The byte to multiply by.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void multiplyBy( uint8_t multiplicand ) {
			if( this->length() == 0 ) return;             // Multiplying by zero is zero.
			SqrlString result( this->length() + 1 );      // A buffer to build the result in.
			uint16_t carry = 0;                           // Digit carried from previous operation
			uint16_t t;                                   // Temporary variable.

			while( this->length() ) {                     // For each byte,
				t = (uint16_t)this->popb_back()           // starting from the back,
					* multiplicand                        // multiply the byte by the multiplicand,
					+ carry;                              // and add any carry byte from the previous operation.
				result.push_back( (uint8_t)(t & 0xFF) );  // Save the result.
				carry = t >> 8;                           // and the carry.
			}
			if( carry ) {                                 // If we have a carry after the last byte,
				result.push_back( (uint8_t)carry );       // Save it in the result.
			}
			result.reverse();                             // Reverse the result buffer,
			this->append( &result );                      // and store the final result.
		}

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Divide the string by a single byte divisor.</summary>
		///
		/// <remarks>This function implements long division in reverse, meaning that the SqrlString is
		/// 		 treated as a number in which the first byte is the least significant.</remarks>
		/// 
		/// <param name="divisor">The divisor.</param>
		///
		/// <returns>The single byte remainder.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		uint8_t divideBy( uint8_t divisor ) {
			if( divisor == 0 ) return 0;               // Cannot divide by zero.
			if( this->length() == 0 ) return divisor;  // Dividing zero by anything is 0 remainder divisor.

			uint8_t *it = this->dend();	               // Start *after* the end of the string.
			uint8_t *end = this->data();               // End when we've processed the first byte of string.
			uint16_t rem = 0;                          // Holds the remainder of most recent divison.
			uint16_t t;                                // Temporary variable.

			do {
				it--;                                  // Move to the previous byte.
				t = (rem << 8) + *it;                  // Take this byte and remainder from previous operation.
				rem = t % divisor;                     // Calculate new remainder.
				*it = (uint8_t)(t / divisor);          // and replace the byte with the result of division.
			} while( it != end );                      // Repeat until we've processed the first byte.

			this->stripTrailingZeros();                // Remove any trailing zeros.
			return (uint8_t)rem;                       // Return the remainder (modulus).
		}
	};
}
#endif // SQRLBIGINT_H

