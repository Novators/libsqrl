#pragma once

#include "SqrlEncoder.h"
#include "SqrlUrlEncode.fwd.h"

class DLL_PUBLIC SqrlUrlEncode : SqrlEncoder
{
public:
	UT_string *encode( UT_string *dest, const uint8_t *src, size_t src_len, bool append = false );
	UT_string *decode( UT_string *dest, const char *src, size_t src_len, bool append = false );
};
