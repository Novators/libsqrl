/** \file SqrlEntropy_Arduino.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLENTROPY_ARDUINO_H
#define SQRLENTROPY_ARDUINO_H

namespace libsqrl
{
    struct sqrl_fast_flux_entropy {};

    void SqrlEntropy::addBracket( uint8_t* seed ) {
        RNG.stir( seed, 32 );
    }
}
#endif // SQRLENTROPY_ARDUINO_H
