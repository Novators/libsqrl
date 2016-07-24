#pragma once

#include <string>
#include "SqrlEncoder.fwd.h"

class DLL_PUBLIC SqrlEncoder
{
public:
	virtual std::string *encode( std::string *dest, const std::string *src, bool append = false ) = 0;
	virtual std::string *decode( std::string *dest, const std::string *src, bool append = false ) = 0;
};
