
#include <string>
#include <sstream>
#include "sqrl_internal.h"
#include "SqrlBase64.h"

UT_string *SqrlBase64::encode( UT_string *dest, const uint8_t *src, size_t src_len, bool append ) {
	static const char B64_ENC_TABLE[64] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '-', '_'
	};

	if( !append ) {
		utstring_renew( dest );
	}
	size_t i = 0;
	uint32_t tmp;
	char str[4];
	while( i < src_len ) {
		tmp = src[i++] << 16;
		if( i < src_len ) 	tmp |= src[i++] << 8;
		if( i < src_len ) 	tmp |= src[i++];

		str[0] = B64_ENC_TABLE[(tmp >> 18) & 0x3F];
		str[1] = B64_ENC_TABLE[(tmp >> 12) & 0x3F];
		str[2] = B64_ENC_TABLE[(tmp >> 6) & 0x3F];
		str[3] = B64_ENC_TABLE[tmp & 0x3F];
		utstring_bincpy( dest, str, 4 );
	}
	i = src_len % 3;
	if( i ) {
		utstring_shrink( dest, 3 - i );
	}
	return dest;
}

UT_string *SqrlBase64::decode( UT_string *dest, const char *src, size_t src_len, bool append ) {
	if( !append ) {
		utstring_renew( dest );
	}
	size_t i = 0;
	int charCount = 0;
	uint32_t tmp = 0, val;
	char str[3];
	size_t input_length = src_len;

	while( i < input_length ) {
		i += this->nextValue( &val, &src[i] );
		if( i <= input_length ) {
			tmp = val << 18;
			charCount++;
		}
		if( i < input_length ) {
			i += this->nextValue( &val, &src[i] );
			if( i <= input_length ) {
				tmp |= val << 12;
				charCount++;
			}
			if( i < input_length ) {
				i += this->nextValue( &val, &src[i] );
				if( i <= input_length ) {
					tmp |= val << 6;
					charCount++;
				}
				if( i < input_length ) {
					i += this->nextValue( &val, &src[i] );
					if( i <= input_length ) {
						tmp |= val;
						charCount++;
					}
				}
			}
		} else {
			break;
		}

		str[0] = (char)((tmp >> 16) & 0xFF);
		str[1] = (char)((tmp >> 8) & 0xFF);
		str[2] = (char)(tmp & 0xFF);
		utstring_bincpy( dest, str, 3 );
	}
	i = charCount % 4;
	if( i ) utstring_shrink( dest, 4 - i );
	return dest;
}

int SqrlBase64::nextValue( uint32_t *nextValue, const char *src ) {
	static const char B64_DEC_TABLE[256] = {
		/*   0 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/*  16 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/*  32 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x3e', '\x00', '\x00',
		/*  48 */	'\x34', '\x35', '\x36', '\x37', '\x38', '\x39', '\x3a', '\x3b', '\x3c', '\x3d', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/*  64 */	'\x00', '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e',
		/*  80 */	'\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x00', '\x00', '\x00', '\x00', '\x3f',
		/*  96 */	'\x00', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20', '\x21', '\x22', '\x23', '\x24', '\x25', '\x26', '\x27', '\x28',
		/* 112 */	'\x29', '\x2a', '\x2b', '\x2c', '\x2d', '\x2e', '\x2f', '\x30', '\x31', '\x32', '\x33', '\x00', '\x00', '\x00', '\x00', '\x00',
		/* 128 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/* 144 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/* 160 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/* 176 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/* 192 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/* 208 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/* 224 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
		/* 240 */	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'
	};
	int i = 0;
	while( src[i] != 0 ) { // End of String
		if( src[i] == 'A' ) { // Legitimately return 0x00
			*nextValue = B64_DEC_TABLE[(int)src[i]];
			return i + 1;
		}
		if( B64_DEC_TABLE[(uint8_t)src[i]] != 0 ) { // Legitimate character
			*nextValue = B64_DEC_TABLE[(int)src[i]];
			//printf( "Selecting: %c (%x)\n", src[i], *nextValue );
			return i + 1;
		}
		i++; // No legitimate character, check the next
	}
	*nextValue = 0;
	return i;
}
