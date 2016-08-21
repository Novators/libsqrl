/** \file SqrlUser.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLUSER_H
#define SQRLUSER_H

#include "sqrl.h"
#include "SqrlString.h"
#include "SqrlKeySet.h"

namespace libsqrl
{
#define USER_FLAG_MEMLOCKED 	0x0001
#define USER_FLAG_T1_CHANGED	0x0002
#define USER_FLAG_T2_CHANGED	0x0004

    typedef struct Sqrl_User_Options
    {
        /** 16 bit Flags, defined at [grc sqrl storage](https://www.grc.com/sqrl/storage.htm) */
        uint16_t flags;
        /** The number of characters to use for password hints (0 to disable) */
        uint8_t hintLength;
        /** The number of seconds to enscrypt */
        uint8_t enscryptSeconds;
        /** Minutes to hold a hint when system is idle */
        uint16_t timeoutMinutes;
    } Sqrl_User_Options;

    class DLL_PUBLIC SqrlUser
    {
        friend class SqrlActionSave;
        friend class SqrlActionGenerate;
        friend class SqrlActionLock;

    public:
        SqrlUser();
        SqrlUser( const char *buffer, size_t buffer_len );
        SqrlUser( SqrlUri *uri );
        ~SqrlUser();

        static void defaultOptions( Sqrl_User_Options *options );

        uint16_t checkFlags( uint16_t flags );
        void clearFlags( uint16_t flags );
        uint8_t getEnscryptSeconds();
        uint16_t getFlags();
        uint8_t getHintLength();
        char* getRescueCode( SqrlAction *t );
        uint16_t getTimeoutMinutes();
        void setEnscryptSeconds( uint8_t seconds );
        void setFlags( uint16_t flags );
        void setHintLength( uint8_t length );
        bool setRescueCode( char *rc );
        void setTimeoutMinutes( uint16_t minutes );
        bool getUniqueId( char *buffer );
        bool uniqueIdMatches( const char *unique_id );
        bool setPassword( const char *password, size_t password_len );
        size_t getPasswordLength();
        SqrlFixedString * key( SqrlAction *action, int key_type );
        SqrlFixedString * scratch();
        bool hasKey( int key_type );
        bool isHintLocked();
        void hintUnlock( SqrlAction *action, SqrlString *hint );
        bool forceRescue( SqrlAction *action );
        bool rekey( SqrlAction *action );
        bool forceDecrypt( SqrlAction *action );
		void *getTag();
		void setTag( void *tag );

    private:
        uint32_t flags;
        uint32_t hint_iterations;
        uint16_t edition;
        Sqrl_User_Options options;
        SqrlStorage *storage;
        SqrlString uniqueId;
        SqrlKeySet *keys;
		void *tag;

        void        ensureKeysAllocated();
        bool        isMemLocked();
        bool        tryLoadPassword( SqrlAction *action, bool retry );
        bool        tryLoadRescue( SqrlAction *action, bool retry );
        bool        regenKeys( SqrlAction *action );
        void        removeKey( int key_type );
        bool _keyGen( SqrlAction *t, int key_type );
        bool loadType2Block( SqrlAction *t, SqrlBlock *block );
        bool saveOrLoadType3Block( SqrlAction *action, SqrlBlock *block, bool saving );
        bool loadType1Block( SqrlAction *t, SqrlBlock *block );
        void _load_unique_id();
    };
}
#endif // SQRLUSER_H
