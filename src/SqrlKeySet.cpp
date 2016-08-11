/** \file SqrlKeySet.cpp
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlKeySet.h"


namespace libsqrl
{

#define USER_FLAG_MEMLOCKED 	0x0001
#define USER_FLAG_T1_CHANGED	0x0002
#define USER_FLAG_T2_CHANGED	0x0004

#define KEY_SET_SIZE 4095
#define PW_OFFSET 1024
#define SCRATCH_OFFSET 1536
#define ALIGN 8

    SqrlKeySet::SqrlKeySet() {
        this->myData = (uint8_t*)sqrl_malloc( KEY_SET_SIZE );
        uint8_t *ptr = this->myData;
        uint8_t *end = this->myData + PW_OFFSET;
        uint16_t classSize = sizeof( class SqrlFixedString );
        if( classSize % ALIGN ) classSize += (ALIGN - (classSize % ALIGN));
        this->slotSize = classSize + SQRL_KEY_SIZE + 1;
        if( this->slotSize % ALIGN ) this->slotSize += (ALIGN - (this->slotSize % ALIGN));
        do {
            new (ptr) SqrlFixedString( SQRL_KEY_SIZE + 1, ptr + sizeof( class SqrlFixedString ), 0 );
            ptr += this->slotSize;
            this->keyCount++;
        } while( ptr < end );
        ptr = this->myData + PW_OFFSET;
        size_t sz = SCRATCH_OFFSET - PW_OFFSET - classSize;
        new (ptr) SqrlFixedString( sz, ptr + classSize, 0 );
        ptr = this->myData + SCRATCH_OFFSET;
        sz = KEY_SET_SIZE - SCRATCH_OFFSET - classSize;
        new (ptr) SqrlFixedString( sz, ptr + classSize, 0 );
    }

    SqrlKeySet::~SqrlKeySet() {
        sqrl_free( this->myData, KEY_SET_SIZE );
    }

    SqrlFixedString * SqrlKeySet::operator[] ( size_t keyType ) {
        switch( keyType ) {
        case SQRL_KEY_PASSWORD:
            return (SqrlFixedString*)(this->myData + PW_OFFSET);
        case SQRL_KEY_SCRATCH:
            return (SqrlFixedString*)(this->myData + SCRATCH_OFFSET);
        default:
            if( keyType > this->keyCount )
                return NULL;
            return (SqrlFixedString*)(this->myData + (keyType * this->slotSize));
        }
    }

}
