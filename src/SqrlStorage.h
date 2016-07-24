#pragma once

#include <stdint.h>
#include <string>
#include "SqrlStorage.fwd.h"
#include "SqrlBlock.fwd.h"
#include "SqrlUri.fwd.h"

class DLL_PUBLIC SqrlStorage
{
public:
	static SqrlStorage *empty();
	static SqrlStorage *from( std::string *buffer );
	static SqrlStorage *from( SqrlUri *uri );

	SqrlStorage *release();

	bool hasBlock(uint16_t blockType);
	bool getBlock(SqrlBlock *block, uint16_t blockType);
	bool putBlock(SqrlBlock *block);
	bool removeBlock(uint16_t blockType);

	bool load(std::string *buffer);
	bool load(SqrlUri *uri);

	std::string *save(Sqrl_Export etype, Sqrl_Encoding encoding);
	bool save(SqrlUri *uri, Sqrl_Export etype, Sqrl_Encoding encoding);

	void getUniqueId(char *unique_id);

private:
	SqrlStorage();
	~SqrlStorage();
	void *data;
};
