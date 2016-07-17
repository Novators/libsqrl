#pragma once

#include "SqrlEncoder.fwd.h"

class DLL_PUBLIC SqrlEncoder
{
public:
	virtual UT_string *encode( UT_string *dest, const uint8_t *src, size_t src_len, bool append = false ) = 0;
	virtual UT_string *decode( UT_string *dest, const char *src, size_t src_len, bool append = false ) = 0;
};
