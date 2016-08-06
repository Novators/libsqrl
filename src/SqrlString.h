/** \file SqrlString.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/
#ifndef SQRLSTRING_H
#define SQRLSTRING_H

#define SQRLSTRING_CHUNK_SIZE 16

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Represents a char or byte string.</summary>
/// 
/// <remarks>
/// This may seem like re-inventing the wheel, but control of memory allocations is necessary on
/// embedded platforms.</remarks> 
////////////////////////////////////////////////////////////////////////////////////////////////////
class DLL_PUBLIC SqrlString
{
public:
	/// <summary>Constructs an empty SqrlString</summary>
	SqrlString() :
		myData( NULL ),
		myCapacity( 0 ) {
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Constructor.</summary>
	///
	/// <param name="in">A C-style NULL terminated string.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	SqrlString( const char *in ) : SqrlString() {
		this->append( in );
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Constructor.</summary>
	///
	/// <param name="in"> An array of characters.</param>
	/// <param name="len">The length of the array.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	SqrlString( const char *in, size_t len ) : SqrlString() {
		this->append( in, len );
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Constructor.</summary>
	///
	/// <param name="in"> Pointer to an array of bytes.</param>
	/// <param name="len">Length of the array..</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	SqrlString( const uint8_t *in, size_t len ) : SqrlString() {
		this->append( in, len );
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Constructor.  Creates an empty SqrlString with a reserved length.</summary>
	///
	/// <param name="len">Length to reserve.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	SqrlString( size_t len ) : SqrlString() {
		this->reserve( len );
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Copy constructor.</summary>
	///
	/// <param name="in">[in] If non-null, pointer to a SqrlString to copy.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	SqrlString( const SqrlString *in ) : SqrlString() {
		if( !in ) return;
		this->append( in );
	}
	
	virtual ~SqrlString() {
		this->deallocate();
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the length of the SqrlString.</summary>
	///
	/// <returns>A size_t.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t length() const {
		if( !this->myData ) return 0;
		return (char*)this->myDend - (char*)this->myData;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the capacity, or total memory currently allocated to the SqrlString.</summary>
	///
	/// <returns>A size_t.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t capacity() const {
		return this->myCapacity;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the string.</summary>
	///
	/// <returns>null if it fails, else a pointer to a C-style, NULL terminate string.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	char * string() {
		return (char*) this->myData;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the end of the string.</summary>
	/// 
	/// <remarks>Use for iteration.</remarks>
	///
	/// <returns>null if it fails, else a pointer to the end of the SqrlString.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	char * strend() {
		return (char*)this->myDend;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the string as a const pointer.</summary>
	///
	/// <returns>null if it fails, else a pointer to a const char.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const char *cstring() const {
		return (char*) this->myData;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the end of the string as a const pointer.</summary>
	///
	/// <returns>null if it fails, else a pointer to a const char.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const char *cstrend() const {
		return (char*)this->myDend;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the data.</summary>
	///
	/// <returns>null if it fails, else a pointer to an array of uint8_t.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint8_t * data() {
		return (uint8_t*) this->myData;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the end of the data.</summary>
	///
	/// <returns>null if it fails, else a pointer to the end of the SqrlString.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint8_t * dend() {
		return (uint8_t*) this->myDend;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the data as a const pointer.</summary>
	///
	/// <returns>null if it fails, else a pointer to a const uint8_t.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const uint8_t *cdata() const {
		return (uint8_t*) this->myData;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the end of the data as a const pointer.</summary>
	///
	/// <returns>null if it fails, else a pointer to a const uint8_t.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const uint8_t *cdend() const {
		return (uint8_t*) this->myDend;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Reserves enough memory to contain a string of the given length.</summary>
	///
	/// <param name="len">The length.</param>
	///
	/// <returns>The actual amount of memory reserved.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t reserve( size_t len ) {
		if( len <= this->myCapacity ) return this->myCapacity;
		size_t chunks = len / SQRLSTRING_CHUNK_SIZE;
		if( len % SQRLSTRING_CHUNK_SIZE != 0 ) chunks++;
		if( this->myData ) {
			this->reallocate( chunks * SQRLSTRING_CHUNK_SIZE );
		} else {
			this->allocate( chunks * SQRLSTRING_CHUNK_SIZE );
		}
		return this->myCapacity;
	}

	/// <summary>Clears this SqrlString.</summary>
	void clear() {
		if( this->myData ) {
			memset( this->myData, 0, this->length() );
			this->myDend = this->myData;
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Appends the given string.</summary>
	///
	/// <param name="string">[in] A SqrlString to append to the end of this SqrlString.  It is not modified.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void append( const SqrlString *string ) {
		if( !string ) return;
		size_t newLen = this->length() + string->length();
		this->reserve( newLen );
		if( this->myCapacity >= newLen ) {
			memcpy( this->myDend, string->cdata(), string->length() );
			this->myDend = (char*)this->myData + newLen;
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Appends the given string.</summary>
	///
	/// <param name="in">Pointer to NULL terminated string to Append.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void append( const char *in ) {
		if( !in ) return;
		size_t inlen = strlen( in );
		size_t newLen = this->length() + inlen;
		this->reserve( newLen );
		if( this->myCapacity >= newLen ) {
			memcpy( this->myDend, in, inlen );
			this->myDend = (char*)this->myData + newLen;
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Appends bytes onto the end of the SqrlString.</summary>
	///
	/// <param name="in"> Pointer to an array of bytes to Append.</param>
	/// <param name="len">The length of the byte array.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void append( const void *in, size_t len ) {
		if( !in ) return;
		size_t newLen = this->length() + len;
		this->reserve( newLen );
		if( this->myCapacity >= newLen ) {
			memcpy( this->myDend, in, len );
			this->myDend = (char*)this->myData + newLen;
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Appends a char to the end of the SqrlString.</summary>
	///
	/// <param name="ch">The char to append.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void push_back( char ch ) {
		this->reserve( this->length() + 1 );
		*((char*)this->myDend) = ch;
		this->myDend = (char*) this->myDend + 1;
		*((char*)this->myDend) = 0;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Appends a byte to the end of the SqrlString.</summary>
	///
	/// <param name="byte">The byte to append.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void push_back( uint8_t byte ) {
		this->reserve( this->length() + 1 );
		*((uint8_t*)this->myDend) = byte;
		this->myDend = (uint8_t*) this->myDend + 1;
		*((uint8_t*)this->myDend) = 0;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes a char from the end of the SqrlString.</summary>
	///
	/// <returns>The value of the char that was removed.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	char popc_back() {
		char *back = (char*)this->myDend - 1;
		if( back < this->myData ) return 0;
		char ret = *back;
		*back = 0;
		this->myDend = back;
		return ret;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Removes a byte from the end of the SqrlString.</summary>
	///
	/// <returns>The value of the byte that was removed.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint8_t popb_back() {
		uint8_t *back = (uint8_t*)this->myDend - 1;
		if( back < this->myData ) return 0;
		uint8_t ret = *back;
		*back = 0;
		this->myDend = back;
		return ret;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Compares this SqrlString to another to determine their relative ordering.</summary>
	///
	/// <param name="str">The constant SqrlString * to compare to this SqrlString.</param>
	///
	/// <returns>Negative if this SqrlString is less than str, 0 if they are equal, 
	/// 		 or positive if it is greater.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int compare( const SqrlString *str ) const {
		size_t ml = this->length();
		size_t sl = str->length();
		size_t cl = ml < sl ? ml : sl;
		int ret = memcmp( this->myData, str->cdata(), cl );
		if( ret != 0 || ml == sl ) {
			return ret;
		}
		cl++;
		return ml < sl ? (int)cl * -1 : (int)cl;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Compares this SqrlString to a C-style string to determine their relative ordering.</summary>
	///
	/// <param name="cstr">The constant character * to compare to this SqrlString.</param>
	///
	/// <returns>Negative if this SqrlString is less than cstr, 0 if they are equal, or positive if it is greater.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int compare( const char *cstr ) const {
		size_t ml = this->length();
		size_t sl = strlen( cstr );
		size_t cl = ml < sl ? ml : sl;
		int ret = memcmp( this->myData, cstr, cl );
		if( ret != 0 || ml == sl ) {
			return ret;
		}
		cl++;
		return ml < sl ? (int)cl * -1 : (int)cl;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Compares this SqrlString to a byte array to determine their relative ordering.</summary>
	///
	/// <param name="buf">   Constant void * to be compared.</param>
	/// <param name="buflen">Size of buf.</param>
	///
	/// <returns>Negative if this SqrlString is less than 'buf', 0 if they are equal, 
	/// 		 or positive if it is greater.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int compare( const void *buf, size_t buflen ) const {
		size_t ml = this->length();
		size_t cl = ml < buflen ? ml : buflen;
		int ret = memcmp( this->myData, buf, cl );
		if( ret != 0 || ml == buflen ) {
			return ret;
		}
		cl++;
		return ml < buflen ? (int)cl * -1 : (int)cl;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Compares a portion of the SqrlString to a byte array to determine their
	/// 		 relative ordering.</summary>
	///
	/// <param name="start">Starting offset.</param>
	/// <param name="end">  Ending offset.</param>
	/// <param name="buf">  Constant void * to be compared.</param>
	///
	/// <returns>Negative if the substring is less than 'buf', 0 if they are equal, or positive if it is
	/// greater.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int compare( size_t start, size_t end, const void *buf ) const {
		if( end < start ) return 1;
		size_t ml = this->length();
		if( end > ml ) return 1;
		size_t cl = end - start;
		return memcmp( this->cdata() + start, buf, cl );
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Erases a range of bytes from this SqrlString.</summary>
	///
	/// <param name="rangeStart">The range start.</param>
	/// <param name="rangeEnd">  The range end.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void erase( size_t rangeStart, size_t rangeEnd ) {
		size_t len = this->length();
		if( rangeStart > rangeEnd || rangeEnd >= len ) return;
		size_t rlen = rangeEnd - rangeStart;
		if( rlen == 0 ) return;
		uint8_t *src = this->data() + rangeEnd;
		uint8_t *dst = this->data() + rangeStart;
		uint8_t *end = this->dend();
		while( src + rlen < end ) {
			memcpy( dst, src, rlen );
			dst += rlen;
			src += rlen;
		}
		if( src < end ) {
			memcpy( dst, src, end - src );
		}
		uint8_t *er = this->dend() - rlen;
		memset( er, 0, rlen );
		this->myDend = this->data() + this->length() - rlen;
	}

protected:

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Destructively allocates len bytes for the SqrlString.</summary>
	/// 
	/// <remarks>If there is alread data in the SqrlString, it will be lost.</remarks>
	///
	/// <param name="len">The length to allocate.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void allocate( size_t len ) {
		if( len <= this->myCapacity ) return;
		if( this->myData ) this->deallocate();
		this->myData = malloc( len + 1 );
		if( this->myData ) {
			this->myCapacity = len;
			this->myDend = this->myData;
			memset( this->myData, 0, len + 1 );
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Allocates additional memory to the SqrlString, retaining it's value.</summary>
	///
	/// <param name="len">The length to allocate.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void reallocate( size_t len ) {
		if( len <= this->myCapacity ) return;
		size_t oldLen = this->length();
		void * oldData = this->myData;
		this->myData = malloc( len + 1 );
		if( this->myData ) {
			this->myCapacity = len;
			this->myDend = (char*)this->myData + oldLen;
			memset( this->myData, 0, len + 1 );
			memcpy( this->myData, oldData, oldLen );
			free( oldData );
		}
	}
	/// <summary>Deallocates this SqrlString.</summary>
	virtual void deallocate() {
		if( this->myData ) {
			free( this->myData );
			this->myData = NULL;
		}
		this->myDend = NULL;
		this->myCapacity = 0;
	}

	void * myData;
	void * myDend;
	size_t myCapacity;
};
#endif // SQRLSTRING_H
