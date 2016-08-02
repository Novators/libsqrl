#pragma once

#include "sqrl.h"

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
	static void update();
	static void	threadFunction();
	static void increment( int amount );
	static void addBracket( uint8_t* seed );

	static void *state;
	static int estimated_entropy;
	static int entropy_target;
	static bool initialized;
	static bool stopping;
	static int sleeptime;
#ifndef ARDUINO
	static std::mutex *mutex;
	static std::thread *thread;
#endif

};