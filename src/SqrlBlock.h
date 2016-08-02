#pragma once

#include <stdint.h>
#include "sqrl.h"

class DLL_PUBLIC SqrlBlock
{
public:
	static SqrlBlock *create();
	static SqrlBlock *create( uint16_t blockType, uint16_t blockLength );

	SqrlBlock *release();

	void        clear();
	bool        init(uint16_t blockType, uint16_t blockLength);
	int         read(uint8_t *data, size_t data_len);
	uint16_t    readInt16();
	uint32_t    readInt32();
	uint8_t     readInt8();
	bool        resize(size_t new_size);
	uint16_t    seek(uint16_t dest, bool offset = false);
	uint16_t	seekBack(uint16_t dest, bool offset = false);
	int         write(uint8_t *data, size_t data_len);
	bool        writeInt16(uint16_t value);
	bool        writeInt32(uint32_t value);
	bool        writeInt8(uint8_t value);
	std::string*	getData(std::string *buf, bool append = false);
	uint8_t*	getDataPointer(bool atCursor = false);
	uint16_t	getBlockLength();
	uint16_t	getBlockType();

private:
	SqrlBlock();
	~SqrlBlock();

	/** The length of the block, in bytes */
	uint16_t blockLength;
	/** The type of block */
	uint16_t blockType;
	/** An offset into the block where reading or writing will occur */
	uint16_t cur;
	/** Pointer to the actual data of the block */
	uint8_t *data;
};

