/** \file SqrlFixedString.h
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/
#ifndef SQRLFIXEDSTRING_H
#define SQRLFIXEDSTRING_H

#include "sqrl.h"
#include "SqrlString.h"

namespace libsqrl
{
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Represents a char or byte string, stored in a fixed memory location.</summary>
    /// 
    /// <remarks>Does not reallocate or move data after initialization.  These strings cannot grow
    ///          past their original buffer size.</remarks>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    class DLL_PUBLIC SqrlFixedString : public SqrlString
    {
    public:
        SqrlFixedString() : SqrlString( SQRL_KEY_SIZE ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        /// 
        /// <remarks>Maximum NULL terminated string length is 'capacity'.</remarks>
        /// 
        /// <param name="capacity">Length of buffer.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlFixedString( size_t capacity ) : SqrlString( capacity ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <remarks>Capacity will be strlen( 'in' )</remarks>
        /// 
        /// <param name="in">A C-style NULL terminated string.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlFixedString( const char *in ) : SqrlString( in ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <remarks>Capacity will be 'len'</remarks>
        /// 
        /// <param name="in"> An array of characters.</param>
        /// <param name="len">The length of the array.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlFixedString( const char *in, size_t len ) : SqrlString( in, len ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <remarks>Capacity will be 'len'.</remarks>
        /// 
        /// <param name="in"> Pointer to an array of bytes.</param>
        /// <param name="len">Length of the array..</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlFixedString( const uint8_t *in, size_t len ) : SqrlString( in, len ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <param name="capacity">The capacity of the buffer.  Maximum string length is one less 
        ///                        than capacity.  Byte arrays may use the entire buffer, but will
        ///                        not be NULL terminated.</param>
        /// <param name="location">[in] Pointer to the data buffer.</param>
        /// <param name="length">  (Optional) the length of data already stored in buffer.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlFixedString( size_t capacity, void * location, size_t length = 0 ) {
            if( !location ) capacity = 0;
            this->myCapacity = capacity;
            this->myData = (uint8_t*)location;
            if( length ) {
                if( length >= capacity ) length = capacity - 1;
                this->myDend = this->myData + length;
            } else {
                this->myDend = this->myData;
            }
            memset( this->myDend, 0, capacity - length + 1 );
            this->selfAllocated = false;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Copy constructor.</summary>
        /// 
        /// <remarks>This SqrlFixedString will have the same capacity and data as 'in'.</remarks>
        ///
        /// <param name="in">[in] If non-null, pointer to a SqrlString to copy.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlFixedString( const SqrlString *in ) : SqrlString() {
            if( !in ) return;
            this->reserve( in->capacity() );
            this->append( in );
        }

        virtual ~SqrlFixedString() {
            this->deallocate();
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Attempts to reserve enough memory to contain a string of the given length.</summary>
        ///
        /// <param name="len">The length.</param>
        ///
        /// <returns>The amount of memory actually reserved.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        size_t reserve( size_t len ) {
            if( this->myCapacity ) return this->myCapacity;         // Already allocated? We're done.
            this->allocate( len );
            return this->myCapacity;
        }

    protected:

        virtual void allocate( size_t len ) {
            if( this->myData ) return;
            SqrlString::allocate( len );
        }

        virtual void reallocate( size_t len ) {
            this->allocate( len );
        }

        /// <summary>Deallocates this SqrlString.</summary>
        virtual void deallocate() {
            if( this->selfAllocated && this->myData ) {
                delete this->myData;
            }
            this->myData = NULL;
            this->myDend = NULL;
            this->myCapacity = 0;
        }

        bool selfAllocated = true;
    };
}
#endif // SQRLFIXEDSTRING_H
