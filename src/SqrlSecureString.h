/** \file SqrlSecureString.h
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/
#ifndef SQRLSECURESTRING_H
#define SQRLSECURESTRING_H

#include "sqrl_internal.h"
#include "SqrlFixedString.h"

namespace libsqrl
{
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Represents a char or byte string, stored in a fixed memory location, and
    ///          prohibited from swapping to disk.</summary>
    /// 
    /// <remarks>Does not reallocate or move data after initialization.  These strings cannot grow
    ///          past their original buffer size.</remarks>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    class DLL_PUBLIC SqrlSecureString : public SqrlFixedString
    {
    public:

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <param name="capacity">Length of buffer.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlSecureString( size_t capacity ) : SqrlFixedString( capacity ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <param name="in">A C-style NULL terminated string.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlSecureString( const char *in ) : SqrlFixedString( in ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <param name="in"> An array of characters.</param>
        /// <param name="len">The length of the array.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlSecureString( const char *in, size_t len ) : SqrlFixedString( in, len ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <param name="in"> Pointer to an array of bytes.</param>
        /// <param name="len">Length of the array..</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlSecureString( const uint8_t *in, size_t len ) : SqrlFixedString( in, len ) {}

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Constructor.</summary>
        ///
        /// <param name="capacity">The capacity of the buffer.</param>
        /// <param name="location">[in] Pointer to the data buffer.</param>
        /// <param name="length">  (Optional) the length of data already stored in buffer.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlSecureString( size_t capacity, void * location, size_t length = 0 )
            : SqrlFixedString( capacity, location, length ) {
            sqrl_mlock( location, capacity );
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Copy constructor.</summary>
        ///
        /// <param name="in">[in] If non-null, pointer to a SqrlString to copy.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlSecureString( const SqrlString *in ) : SqrlFixedString( in ) {}

        virtual ~SqrlSecureString() {
            this->deallocate();
        }

    protected:

        virtual void allocate( size_t len ) {
            if( this->myData ) return;
            SqrlString::allocate( len );
            if( this->myData ) {
                sqrl_mlock( this->myData, this->myCapacity );
            }
        }

        virtual void reallocate( size_t len ) {
            this->allocate( len );
        }

        /// <summary>Deallocates this SqrlString.</summary>
        virtual void deallocate() {
            if( this->myData ) {
                sqrl_munlock( this->myData, this->myCapacity ); // Also zeros buffer.
            }
            if( this->selfAllocated && this->myData ) {
                free( this->myData );
            }
            this->myData = NULL;
            this->myDend = NULL;
            this->myCapacity = 0;
        }
    };
}
#endif // SQRLSECURESTRING_H
