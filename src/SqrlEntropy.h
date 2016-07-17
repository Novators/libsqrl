#pragma once

#include "sqrl.h"
#include "SqrlEntropy.fwd.h"

class DLL_PUBLIC SqrlEntropy
{
public:
	static void start();
	static void stop();

	static void add( uint8_t *buf, size_t buf_len );
	static int estimate();
	static int get( uint8_t *buf, int desired_entropy, bool blocking = true );
	static int bytes( uint8_t* buf, int nBytes );

private:
	static void *state;
	static void update();
	static SQRL_THREAD_FUNCTION_RETURN_TYPE	thread( SQRL_THREAD_FUNCTION_INPUT_TYPE input );
	static void increment( struct sqrl_entropy_pool *pool, int amount );

};