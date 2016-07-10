/** @file encdec.c Encode / Decode functions 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "sqrl.h"

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
// 0x45
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

/*
   0 	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
  16 	'\x01', '\x00', '\x00', '\x00', '\x5c', '\x08', '\x00', '\x00', '\xc0', '\x99', '\x76', '\xb7', '\xe0', '\x96', '\x76', '\xb7',
  32 	'\x45', '\x82', '\x04', '\x08', '\x8c', '\x1a', '\x61', '\xb7', '\xc8', '\x81', '\x04', '\x08', '\x01', '\x3e', '\x00', '\x00',
  48 	'\x34', '\x35', '\x36', '\x37', '\x38', '\x39', '\x3a', '\x3b', '\x3c', '\x3d', '\x78', '\xb7', '\xe0', '\xe3', '\xff', '\xbf',
  64 	'\xcf', '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e',
  80 	'\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\xb7', '\x01', '\x00', '\x00', '\x3f',
  96 	'\x00', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20', '\x21', '\x22', '\x23', '\x24', '\x25', '\x26', '\x27', '\x28',
 112 	'\x29', '\x2a', '\x2b', '\x2c', '\x2d', '\x2e', '\x2f', '\x30', '\x31', '\x32', '\x33', '\x00', '\x00', '\x00', '\x00', '\x00',
 128 	'\xd0', '\xe3', '\xff', '\xbf', '\xc4', '\xe3', '\xff', '\xbf', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
 144 	'\x00', '\x00', '\x00', '\x00', '\x10', '\xe4', '\xff', '\xbf', '\x68', '\x66', '\x78', '\xb7', '\x45', '\x82', '\x04', '\x08',
 160 	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
 176 	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
 192 	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
 208 	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
 224 	'\x66', '\xf5', '\xff', '\xbf', '\x1e', '\x31', '\x67', '\xb7', '\x79', '\x0b', '\x72', '\xb7', '\xbc', '\x96', '\x04', '\x08',
 240 	'\xb8', '\xe3', '\xff', '\xbf', '\xec', '\x82', '\x04', '\x08', '\xf4', '\xbf', '\x75', '\xb7', '\xbc', '\x96', '\x04', '\x08'
*/

static const char hex[] = "0123456789ABCDEF";

/**
 * Convert a hex-encoded string to an unsigned integer.
 * 
 * @param hex Pointer to string.
 * @param hex_len Length of string.
 * @return Decoded unsigned integer.
 */

uint32_t sqrl_hex2uint( const char *hex )
{
	return (uint32_t) strtol( hex, NULL, 16 );	
}

/**
 * URL-Encode a string.
 *
 * Copies \p src to \p dest, converting any unsafe characters into %-encoded triplets.
 *
 * @warning If \p dest is NULL, a new \p UT_string will be allocated and returned.  Your code must be prepared to capture and (eventually) free the returned value if you allow \p dest to be NULL.
 *
 * @param dest Pointer to a \p UT_string to receive the result, or NULL.
 * @param src Pointer to a NULL terminated string containing the source.
 * @return Pointer to the URL-Encoded \p UT_string.
 */

UT_string *sqrl_urlencode( UT_string *dest, const char *src ) 
{
	const char *p;
	char str[3];
	str[0] = '%';
	utstring_renew(dest);
	for( p = src; p[0] != 0; p++ ) {
		if( p[0] == ' ' ) {
			utstring_bincpy( dest, "+", 1 );
			continue;
		}
		if( (p[0] >= '0' && p[0] <= '9') ||
			(p[0] >= 'A' && p[0] <= 'Z') ||
			(p[0] >= 'a' && p[0] <= 'z') ) {
			utstring_bincpy( dest, p, 1 );
			continue;
		}
		str[1] = hex[p[0]>>4];
		str[2] = hex[p[0]&0x0F];
		utstring_bincpy( dest, str, 3 );
	}
	return dest;
}

/**
 * Decodes a url-encoded string.
 *
 * Copies \p src to \p dest, converting any %-encoded triplets into the characters they represent.
 *
 * @warning If \p dest is NULL, a new \p UT_string will be allocated and returned.  Your code must be prepared to capture and (eventually) free the returned value if you allow \p dest to be NULL.
 *
 * @param dest Pointer to a \p UT_string to receive the result, or NULL.
 * @param src Pointer to a NULL terminated string containing the source.
 * @return Pointer to the decoded \p UT_string.
 */

UT_string *sqrl_urldecode( UT_string *dest, const char *src )
{
	const char *p;
	char dc;
	int i;
	char tmp;
	utstring_renew(dest);
	for( p = src; p[0] != 0; p++ ) {
		if( p[0] == '+' ) {
			utstring_bincpy( dest, " ", 1 );
		} else if( p[0] == '%' && strlen(p) > 2 ) {
			for( i = 1; i <= 2; i++ ) {
				dc = p[i];
				if( dc >= '0' && dc <= '9' ) {
					dc -= 48;
				} else if( dc >= 'a' && dc <= 'f') {
					dc -= 87;
				} else if( dc >= 'A' && dc <= 'F' ) {
					dc -= 55;
				} else {
					dc = (char)255;
				}
				if( dc < 16 ) {
					if( i == 1 ) {
						tmp = dc << 4;
					} else {
						tmp |= dc;
					}
				}
			}
			utstring_bincpy( dest, &tmp, 1 );
			p += 2;
		} else {
			utstring_bincpy( dest, p, 1 );
		}
	}
	return dest;
}

/**
 * base64url encode a string of bytes, appending the result to \p dest.
 * 
 * @param dest Pointer to an allocated and initialized \p UT_string to contain the result.
 * @param src Pointer to a string of bytes to be encoded.
 * @param src_len The length (in bytes) of \p src.
 */

void sqrl_b64u_encode_append( UT_string *dest, const uint8_t *src, size_t src_len )
{
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
#if SQRL_BASE64_PAD_CHAR == 0x00
		utstring_shrink( dest, 3-i );
#else
		for( i = 3-i; i > 0; i-- ) {
			utstring_body(dest)[utstring_len(dest)-i] = SQRL_BASE64_PAD_CHAR;
		}
#endif
	}
}

/**
 * base64url-encode a string of bytes.
 *
 * @warning If \p dest is NULL, a new \p UT_string will be allocated and returned.  Your code must be prepared to capture and (eventually) free the returned value if you allow \p dest to be NULL.
 *
 * @param dest Pointer to an allocated and initialized \p UT_string, or NULL.
 * @param src Pointer to a string of bytes to be encoded.
 * @param src_len The length (in bytes) of \p src.
 * @return Pointer to the result \p UT_string.
 */

UT_string *sqrl_b64u_encode( UT_string *dest, const uint8_t *src, size_t src_len )
{
	utstring_renew( dest );
	sqrl_b64u_encode_append( dest, src, src_len );
	return dest;
}

/**
 * @internal
 * Finds and decodes the next legitimate character of a base64url string.
 *
 * If no legitimate character is found, sets \p nextValue to 0x00, and returns \p strlen(src).
 * Since 0x00 can be a legitimate return value, it is necessary to verify that the returned offset is less than the string length.
 *
 * @todo There's probably a better way to signal failure?
 * 
 * @param nextValue Pointer to a \p uint32_t to hold the result.
 * @param src Pointer to a NULL terminated source string.
 * @return The offset of the legitimate character found.
 */
static int sqrl_b64u_decode_next_value(uint32_t *nextValue, const char *src) {
	int i = 0;
	while( src[i] != 0 ) { // End of String
		if( src[i] == 'A' ) { // Legitimately return 0x00
			*nextValue = B64_DEC_TABLE[(int)src[i]];
			return i+1;
		}
		if( B64_DEC_TABLE[(uint8_t)src[i]] != 0 ) { // Legitimate character
			*nextValue = B64_DEC_TABLE[(int)src[i]];
			//printf( "Selecting: %c (%x)\n", src[i], *nextValue );
			return i+1;
		}
		i++; // No legitimate character, check the next
	}
	*nextValue = 0;
	return i;
}

/**
 * Decode a base64url-encoded string, appending the result to \p dest.
 *
 * Skips invalid characters.
 * 
 * @param dest Pointer to an allocated and initialized \p UT_string to contain the result.
 * @param src Pointer to a string to be decoded.
 * @param src_len The length (in bytes) of \p src.
 */

void sqrl_b64u_decode_append( UT_string *dest, const char *src, size_t src_len )
{
	size_t i = 0;
	int charCount = 0;
	uint32_t tmp = 0, val;
	char str[3];
#if SQRL_BASE64_PAD_CHAR == 0x00
	size_t input_length = src_len;
#else
	char *p = strchr( src, SQRL_BASE64_PAD_CHAR );;
	size_t input_length = (p && (p <= src + src_len )) ? p - src : src_len;
#endif
	
	while( i < input_length ) {
		i += sqrl_b64u_decode_next_value( &val, &src[i] );
		if( i <= input_length ) {
			tmp = val << 18;
			charCount++;
		}
		if( i < input_length ) {
			i += sqrl_b64u_decode_next_value( &val, &src[i] );
			if( i <= input_length ) {
				tmp |= val << 12;
				charCount++;
			}
			if( i < input_length ) {
				i += sqrl_b64u_decode_next_value( &val, &src[i] );
				if( i <= input_length ) {
					tmp |= val << 6;
					charCount++;
				}
				if( i < input_length ) {
					i += sqrl_b64u_decode_next_value( &val, &src[i] );
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
	if( i ) utstring_shrink( dest, 4-i );
}

/**
 * Decode a base64url-encoded string.
 *
 * Skips invalid characters.
 *
 * @warning If \p dest is NULL, a new \p UT_string will be allocated and returned.  Your code must be prepared to capture and (eventually) free the returned value if you allow \p dest to be NULL.
 *
 * @param dest Pointer to an allocated and initialized \p UT_string, or NULL.
 * @param src Pointer to a string to decode.
 * @param src_len The length (in bytes) of \p src.
 * @return Pointer to the result \p UT_string.
 */

UT_string *sqrl_b64u_decode( UT_string * dest, const char *src, size_t src_len )
{
	utstring_renew( dest );
	sqrl_b64u_decode_append( dest, src, src_len );
	return dest;
}
