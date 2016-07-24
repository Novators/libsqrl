
#include <string>
#include <sstream>
#include "sqrl_internal.h"
#include "SqrlUrlEncode.h"

std::string *SqrlUrlEncode::encode( std::string *dest, const uint8_t *src, size_t src_len, bool append ) {
	static const char hex[] = "0123456789ABCDEF";
	if( !dest ) {
		dest = new std::string();
	} else {
		if( !append ) dest->clear();
	}
	const char *p;
	char str[3];
	str[0] = '%';
	for( p = (char*)src; p[0] != 0; p++ ) {
		if( p[0] == ' ' ) {
			dest->append( 1, '+' );
			continue;
		}
		if( (p[0] >= '0' && p[0] <= '9') ||
			(p[0] >= 'A' && p[0] <= 'Z') ||
			(p[0] >= 'a' && p[0] <= 'z') ) {
			dest->append( p, 1 );
			continue;
		}
		str[1] = hex[p[0] >> 4];
		str[2] = hex[p[0] & 0x0F];
		dest->append( str, 3 );
	}
	return dest;
}

std::string *SqrlUrlEncode::decode( std::string *dest, const char *src, size_t src_len, bool append ) {
	if( !dest ) {
		dest = new std::string();
	} else {
		if( !append ) dest->clear();
	}
	const char *p;
	char dc;
	int i;
	char tmp;
	for( p = src; p[0] != 0; p++ ) {
		if( p[0] == '+' ) {
			dest->append( 1, ' ' );
		} else if( p[0] == '%' && strlen( p ) > 2 ) {
			for( i = 1; i <= 2; i++ ) {
				dc = p[i];
				if( dc >= '0' && dc <= '9' ) {
					dc -= 48;
				} else if( dc >= 'a' && dc <= 'f' ) {
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
			dest->append( 1, tmp );
			p += 2;
		} else {
			dest->append( p, 1 );
		}
	}
	return dest;
}

