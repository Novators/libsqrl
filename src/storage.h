#ifndef SQRL_STORAGE_H_INCLUDED
#define SQRL_STORAGE_H_INCLUDED

#ifndef DLL_PUBLIC
#define DLL_PUBLIC _declspec(dllimport)
#endif

#include <stdint.h>
#include "sqrl_expert.h"
#include "uri.h"


/**
* Parses a URL and stores the parts that libsqrl needs.
*/
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


#endif //SQRL_STORAGE_H_INCLUDED