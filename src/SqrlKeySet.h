/** \file SqrlKeySet.h
*
* \author Adam Comley
*
* This file is part of libsqrl.  It is released under the MIT license.
* For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLKEYSET_H
#define SQRLKEYSET_H

#include "sqrl.h"
#include "SqrlFixedString.h"

#define SQRL_KEY_MK           0
#define SQRL_KEY_ILK          1
#define SQRL_KEY_PIUK0        2
#define SQRL_KEY_PIUK1        3
#define SQRL_KEY_PIUK2        4
#define SQRL_KEY_PIUK3        5
#define SQRL_KEY_IUK          6
#define SQRL_KEY_LOCAL        7
#define SQRL_KEY_RESCUE_CODE  8
#define SQRL_KEY_PASSWORD     9
#define SQRL_KEY_SCRATCH     10

namespace libsqrl
{
    class SqrlKeySet
    {
    private:
        uint8_t *myData = NULL;
        uint8_t *myScratch = NULL;
        uint8_t mySlotSize = 0;

    public:
        SqrlKeySet();
        ~SqrlKeySet();
        SqrlFixedString * operator[] ( size_t keyType );
    };
}
#endif // SQRLKEYSET_H
