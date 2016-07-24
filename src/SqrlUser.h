#pragma once

#include "SqrlUser.fwd.h"
#include "SqrlUri.fwd.h"
#include "SqrlBlock.fwd.h"
#include "SqrlStorage.fwd.h"
#include "SqrlCrypt.fwd.h"
#include "SqrlActionSave.fwd.h"

#define USER_MAX_KEYS 16

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

#define KEY_MK           1
#define KEY_ILK          2
#define KEY_PIUK0        3
#define KEY_PIUK1        4
#define KEY_PIUK2        5
#define KEY_PIUK3        6
#define KEY_IUK          7
#define KEY_LOCAL        8
#define KEY_RESCUE_CODE  9
#define KEY_PASSWORD    10

#define KEY_PASSWORD_MAX_LEN 512
#define KEY_SCRATCH_SIZE 2048

#pragma pack(push,8)
struct Sqrl_Keys
{
	uint8_t keys[USER_MAX_KEYS][SQRL_KEY_SIZE];		//  512   (28 * 32)
	size_t password_len;							//    8
	char password[KEY_PASSWORD_MAX_LEN];			//  512
													// Internal Use Only:
	uint8_t scratch[KEY_SCRATCH_SIZE];				// 2048
													// 3080 bytes
};
#pragma pack(pop)


class DLL_PUBLIC SqrlUser
{
	friend class SqrlActionSave;
	friend class SqrlActionGenerate;

public:
	static SqrlUser *create();
	static SqrlUser *create( const char *buffer, size_t buffer_len );
	static SqrlUser *create( SqrlUri *uri );

	static void        defaultOptions( Sqrl_User_Options *options );
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
	void hintLock();
	uint8_t* key( SqrlAction *transaction, int key_type );
	uint8_t* scratch();
	bool hasKey( int key_type );
	bool isHintLocked();
	void hintUnlock( SqrlAction *transaction, char *hint, size_t length );
	bool forceRescue( SqrlAction *transaction );
	bool rekey( SqrlAction *transaction );
	bool forceDecrypt( SqrlAction *transaction );
	void exportAll( const char *uri, Sqrl_Encoding encoding );
	void exportRescue( const char *uri, Sqrl_Encoding encoding );



private:
	uint8_t lookup[USER_MAX_KEYS];
	uint32_t flags;
	uint32_t hint_iterations;
	Sqrl_User_Options options;
	std::mutex *referenceCountMutex;
	int referenceCount;
	SqrlStorage *storage;
	char uniqueId[SQRL_UNIQUE_ID_LENGTH + 1];
	struct Sqrl_Keys *keys;

	SqrlUser();
	SqrlUser( const char *buffer, size_t buffer_len );
	SqrlUser( SqrlUri *uri );
	~SqrlUser();

	static int         enscryptCallback( int percent, void *data );
	void        ensureKeysAllocated();
	bool        isMemLocked();
	bool        tryLoadPassword( SqrlAction *transaction, bool retry );
	bool        tryLoadRescue( SqrlAction *transaction, bool retry );
	void        memLock();
	void        memUnlock();
	uint8_t*    newKey( int key_type );
	bool        regenKeys( SqrlAction *transaction );
	void        removeKey( int key_type );
	bool        updateStorage( SqrlAction *transaction );
	void initialize();
	bool _keyGen( SqrlAction *t, int key_type, uint8_t *key );
	SqrlCrypt* _init_t2( SqrlAction *t, SqrlBlock *block, bool forSaving );
	bool sul_block_2( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sus_block_2( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sul_block_3( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sus_block_3( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sul_block_1( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sus_block_1( SqrlAction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	static void saveCallbackData( struct Sqrl_User_s_callback_data *cbdata );
	void _load_unique_id();
	bool save( SqrlActionSave *transaction );
	bool saveToBuffer( SqrlActionSave *transaction );
};

