#pragma once

#include <stdint.h>
#include "utstring.h"
#include "storage.fwd.h"
#include "block.fwd.h"
#include "uri.fwd.h"

class DLL_PUBLIC SqrlStorage
{
public:
	SqrlStorage();
	~SqrlStorage();

	bool hasBlock(uint16_t blockType);
	bool getBlock(SqrlBlock *block, uint16_t blockType);
	bool putBlock(SqrlBlock *block);
	bool removeBlock(uint16_t blockType);

	bool load(UT_string *buffer);
	bool load(SqrlUri *uri);

	bool save(UT_string *buffer, Sqrl_Export etype, Sqrl_Encoding encoding);
	bool save(SqrlUri *uri, Sqrl_Export etype, Sqrl_Encoding encoding);

	void getUniqueId(char *unique_id);

private:
	void *data;
};
