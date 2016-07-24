#pragma once

#include "SqrlEncoder.h"
#include "SqrlUrlEncode.fwd.h"

class DLL_PUBLIC SqrlUrlEncode : SqrlEncoder
{
public:
	std::string *encode( std::string *dest, const uint8_t *src, size_t src_len, bool append = false );
	std::string *decode( std::string *dest, const char *src, size_t src_len, bool append = false );
};
