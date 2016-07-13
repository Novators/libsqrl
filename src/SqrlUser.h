#pragma once

#include "SqrlUser.fwd.h"
#include "SqrlUri.fwd.h"
#include "SqrlBlock.fwd.h"
#include "SqrlStorage.fwd.h"

class DLL_PUBLIC SqrlUser
{
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
	char* getRescueCode( SqrlTransaction *t );
	uint16_t getTimeoutMinutes();
	void setEnscryptSeconds( uint8_t seconds );
	void setFlags( uint16_t flags );
	void setHintLength( uint8_t length );
	bool setRescueCode( char *rc );
	void setTimeoutMinutes( uint16_t minutes );
	bool getUniqueId( char *buffer );
	bool uniqueIdMatches( const char *unique_id );
	bool setPassword( char *password, size_t password_len );
	size_t getPasswordLength();
	bool save( SqrlTransaction *transaction );
	bool saveToBuffer( SqrlTransaction *transaction );
	void hintLock();
	uint8_t* key( SqrlTransaction *transaction, int key_type );
	uint8_t* scratch();
	bool hasKey( int key_type );
	bool isHintLocked();
	void hintUnlock( SqrlTransaction *transaction, char *hint, size_t length );
	bool forceRescue( SqrlTransaction *transaction );
	bool rekey( SqrlTransaction *transaction );
	bool forceDecrypt( SqrlTransaction *transaction );
	void exportAll( const char *uri, Sqrl_Encoding encoding );
	void exportRescue( const char *uri, Sqrl_Encoding encoding );



private:
	uint8_t lookup[USER_MAX_KEYS];
	uint32_t flags;
	uint32_t hint_iterations;
	Sqrl_User_Options options;
	SqrlMutex referenceCountMutex;
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
	bool        tryLoadPassword( SqrlTransaction *transaction, bool retry );
	bool        tryLoadRescue( SqrlTransaction *transaction, bool retry );
	void        memLock();
	void        memUnlock();
	uint8_t*    newKey( int key_type );
	bool        regenKeys( SqrlTransaction *transaction );
	void        removeKey( int key_type );
	bool        updateStorage( SqrlTransaction *transaction );
	void initialize();
	bool _keyGen( SqrlTransaction *t, int key_type, uint8_t *key );
	bool _init_t2(
		SqrlTransaction *t,
		Sqrl_Crypt_Context *sctx,
		SqrlBlock *block,
		bool forSaving );
	bool sul_block_2( SqrlTransaction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sus_block_2( SqrlTransaction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sul_block_3( SqrlTransaction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sus_block_3( SqrlTransaction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sul_block_1( SqrlTransaction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	bool sus_block_1( SqrlTransaction *t, SqrlBlock *block, struct Sqrl_User_s_callback_data cbdata );
	static void saveCallbackData( struct Sqrl_User_s_callback_data *cbdata );
	void _load_unique_id();
};

