/** @file sqrl_expert.h 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/  
#ifndef SQRL_EXPERT_H_INCLUDED
#define SQRL_EXPERT_H_INCLUDED


#include "sqrl_client.h"
#include "sqrl_server.h"

#define SQRL_BLOCK_USER                     0x0001
#define SQRL_BLOCK_RESCUE                   0x0002
#define SQRL_BLOCK_PREVIOUS                 0x0003

// Defaults for new Identities
#define SQRL_DEFAULT_N_FACTOR                    9
#define SQRL_DEFAULT_FLAGS                    0xF1
#define SQRL_DEFAULT_HINT_LENGTH                 4
#define SQRL_DEFAULT_TIMEOUT_MINUTES            15



/**
\defgroup entropy Entropy Harvester

Modeled after GRC's assembly implementation, this is a cross-platform entropy harvester.  
We collect entropy from various sources (operating system dependant) at regular intervals, 
and feed them into a SHA-512 hash.  The hash state is constantly being modified until a
caller asks for entropy; then the hash is finalized and the 512 bit (64 byte) result is
returned to the caller.  The hash is then re-opened and filled with more entropy.

When first initialized, and after entropy has been retrieved, we collect about 100 
samples per second.  After we reach the target entropy estimate (512 samples), collection
is throttled to approximately 5 samples per second.  This allows us to quickly build 
entropy, and then reduce CPU and power usage when we have enough.  If you want more entropy,
or want to add your own sources, you can do so with the \p sqrl_entropy_add function.

@{ */

/** The Entropy Pool Object */
DLL_PUBLIC void sqrl_entropy_add( uint8_t*, size_t );
DLL_PUBLIC int  sqrl_entropy_estimate();
DLL_PUBLIC int  sqrl_entropy_get( uint8_t*, int );
DLL_PUBLIC int  sqrl_entropy_get_blocking( uint8_t*, int );
DLL_PUBLIC int  sqrl_entropy_bytes( uint8_t*, int );
/** @} */ // endgroup entropy

#include "block.h"
#include "storage.h"

#endif // SQRL_EXPERT_H_INCLUDED