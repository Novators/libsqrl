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
        static int countUsers();

        uint16_t checkFlags( uint16_t flags );
        void clearFlags( uint16_t flags );
        static SqrlUser*  find( const char *unique_id );
        void release();
        void hold();
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

    private:
        uint32_t flags;
        uint32_t hint_iterations;
        Sqrl_User_Options options;
#ifndef ARDUINO
        std::mutex referenceCountMutex;
#endif
        int referenceCount;
        SqrlStorage *storage;
        SqrlString uniqueId;
        SqrlKeySet *keys;

        static int         enscryptCallback( int percent, void *data );
        void        ensureKeysAllocated();
        bool        isMemLocked();
        bool        tryLoadPassword( SqrlAction *action, bool retry );
        bool        tryLoadRescue( SqrlAction *action, bool retry );
        void        memLock();
        void        memUnlock();
        bool        regenKeys( SqrlAction *action );
        void        removeKey( int key_type );
        bool        updateStorage( SqrlAction *action );
        void initialize();
        bool _keyGen( SqrlAction *t, int key_type );
        SqrlCrypt* _init_t2( SqrlAction *t, SqrlBlock *block, bool forSaving );
        bool sul_block_2( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
        bool sus_block_2( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
        bool sul_block_3( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
        bool sus_block_3( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
        bool sul_block_1( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
        bool sus_block_1( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
        static void saveCallbackData( struct Sqrl_User_s_callback_data *cbdata );
        void _load_unique_id();
        bool save( SqrlActionSave *action );
        bool saveToBuffer( SqrlActionSave *action );
    };
}
#endif // SQRLUSER_H
