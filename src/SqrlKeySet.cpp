/** \file SqrlKeySet.cpp
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlKeySet.h"

// Total data size is 4096 bytes.
#define KEY_SET_SIZE 4096
// Password can be up to 1024 bytes.
#define PW_LENGTH 1024
// Values are 8 byte aligned.
#define ALIGN 8

namespace libsqrl
{

    SqrlKeySet::SqrlKeySet() {
        this->myData = (uint8_t*)sqrl_malloc( KEY_SET_SIZE );
        uint8_t *ptr = this->myData;
        uint8_t classSize = sizeof( class SqrlFixedString );
        if( classSize % ALIGN ) classSize += (ALIGN - (classSize % ALIGN));
        size_t slotSize = classSize + SQRL_KEY_SIZE + 1;
        if( slotSize % ALIGN ) slotSize += (ALIGN - (slotSize % ALIGN));
        this->mySlotSize = (uint8_t)slotSize;
        for( int keyCount = 0; keyCount < SQRL_KEY_PASSWORD; keyCount++ ) {
            new (ptr) SqrlFixedString( SQRL_KEY_SIZE, ptr + classSize, 0 );
            ptr += slotSize;
        }
        slotSize = classSize + PW_LENGTH + 1;
        if( slotSize % ALIGN ) slotSize += (ALIGN - (slotSize % ALIGN));
        new (ptr) SqrlFixedString( PW_LENGTH, ptr + classSize, 0 );
        ptr += slotSize;
        this->myScratch = ptr;

        slotSize = this->myData + KEY_SET_SIZE - ptr - classSize - 1;
        new (ptr) SqrlFixedString( slotSize, ptr + classSize, 0 );
    }

    SqrlKeySet::~SqrlKeySet() {
        sqrl_free( this->myData, KEY_SET_SIZE );
    }

    SqrlFixedString * SqrlKeySet::operator[] ( size_t keyType ) {
        if( keyType < SQRL_KEY_SCRATCH ) {
            return (SqrlFixedString*)(this->myData + (keyType * this->mySlotSize));
        }
        if( keyType == SQRL_KEY_SCRATCH ) {
            return (SqrlFixedString*)(this->myScratch);
        }
        return NULL;
    }

}
