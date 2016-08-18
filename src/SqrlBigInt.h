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
                char c = this->popc_back();            // Remove the last byte from buffer.
                if( c != 0 ) {                         // If it is not zero,
                    this->push_back( c );              // put it back,
                    break;                             // and end.
                }                                      // Otherwise, discard it and repeat.
            }
        }

    public:
        SqrlBigInt() : SqrlString() {}
        SqrlBigInt( const SqrlString *in ) : SqrlString( in ) {}
        SqrlBigInt( size_t len ) : SqrlString( len ) {}
        SqrlBigInt( const uint8_t *in, size_t len ) : SqrlString( in, len ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Adds a single byte to the string.</summary>
        ///
        /// <param name="operand">The byte to add.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        void add( uint8_t operand ) {
            if( this->length() == 0 ) {                // If the buffer is empty,
                this->append( (char)operand, 1 );      // just store the operand.
                return;
            }
            uint16_t t = operand;                      // Temporary variable, initialized with operand.
            
            uint8_t *it = this->dend();                // Starting *after* the last byte in the buffer,
            uint8_t *end = this->data();               // and ending when the first byte has been processed:
            do {
                it--;                                  // Move to the previous byte in buffer.
                t += *it;                              // Add the byte and any carry value.
                *it = (uint8_t)t;                      // Store result byte,
                t = t >> 8;                            // and carry any overflow to next operation.
            } while( t && it != end );                 // If we have processed the first byte in buffer,
                                                       // or we no longer have a carry byte, we're done.

            if( t ) {                                  // If there is still a carry,
                this->insert( 0, (uint8_t)t );         // Store it as a new byte at beginning of buffer.
            }
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Multiplies the string by a single byte.</summary>
        ///
        /// <param name="multiplicand">The byte to multiply by.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        void multiplyBy( uint8_t multiplicand ) {
            if( this->length() == 0 ) return;          // Multiplying by zero is zero.
            uint16_t t = 0;                            // Temporary variable.
            
            uint8_t *it = this->dend();                // Starting *after* the last byte in the buffer,
            uint8_t *end = this->data();               // and ending when the first byte has been processed:
            do {
                it--;                                  // Move to the previous byte in buffer.
                t += ((uint16_t)*it * multiplicand);   // Multiply the byte by multiplicand, and add any carry.
                *it = (uint8_t)t;                      // Store the result byte,
                t = t >> 8;                            // And carry overflow to next operation.
            } while( it != end );                      // Did we just process the first byte in buffer?

            if( t ) {                                  // If we still have a carry,
                this->insert( 0, (uint8_t)t );         // Insert it as a new byte at beginning of buffer.
            }
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Divide the string by a single byte divisor.</summary>
        ///
        /// <remarks>This function implements long division in reverse, meaning that the SqrlString is
        ///          treated as a number in which the first byte is the least significant.</remarks>
        /// 
        /// <param name="divisor">The divisor.</param>
        ///
        /// <returns>The single byte remainder.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        uint8_t divideBy( uint8_t divisor ) {
            if( divisor == 0 ) return 0;               // Cannot divide by zero.
            if( this->length() == 0 ) return divisor;  // Dividing zero by anything is 0 remainder divisor.

            uint16_t t = 0;                            // Temporary variable.

            uint8_t *it = this->dend();	               // Starting *after* the end of the string.
            uint8_t *end = this->data();               // And ending when the first byte has been processed:
            do {
                it--;                                  // Move to the previous byte.
                t = (uint16_t)*it | (t << 8);          // Shift remainder 8 bits left, and add current byte.
                *it = (uint8_t)(t / divisor);          // Divide by divisor and store result.
                t = (t % divisor);                     // Carry remainder.
            } while( it != end );                      // Repeat until we've processed the first byte.

            this->stripTrailingZeros();                // Remove any trailing zeros.
            return (uint8_t)t;                         // Return the remainder (modulus).
        }
    };
}
#endif // SQRLBIGINT_H

