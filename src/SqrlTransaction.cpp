/** @file transaction.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#include "sqrl_internal.h"
#include "sqrl.h"
#include "SqrlTransaction.h"
#include "SqrlUri.h"
#include "SqrlUser.h"

struct Sqrl_Transaction_List {
	SqrlTransaction *transaction;
	struct Sqrl_Transaction_List *next;
};

struct Sqrl_Transaction_List *SQRL_TRANSACTION_LIST = NULL;

#if defined(DEBUG) && DEBUG_PRINT_TRANSACTION_COUNT==1
#define PRINT_TRANSACTION_COUNT(tag) \
int _ptcI = 0;\
struct Sqrl_Transaction_List *_ptcC = SQRL_TRANSACTION_LIST;\
while( _ptcC ) {\
    _ptcI++;\
    _ptcC = _ptcC->next;\
}\
printf( "%10s: %d\n", tag, _ptcI )
#else
#define PRINT_TRANSACTION_COUNT(tag)
#endif

SqrlTransaction::SqrlTransaction( Sqrl_Transaction_Type type)
{
    struct Sqrl_Transaction_List *list = (struct Sqrl_Transaction_List*)calloc( 1, sizeof( struct Sqrl_Transaction_List ));
	this->type = type;
    this->referenceCount = 1;
    this->mutex = sqrl_mutex_create();
    list->transaction = this;
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.transaction );
    list->next = SQRL_TRANSACTION_LIST;
    SQRL_TRANSACTION_LIST = list;
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.transaction );
}


int SqrlTransaction::countTransactions()
{
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.transaction );
    int i = 0;
    struct Sqrl_Transaction_List *list = SQRL_TRANSACTION_LIST;
    while( list ) {
        i++;
        list = list->next;
    }
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.transaction );
    return i;
}

void SqrlTransaction::hold()
{
    struct Sqrl_Transaction_List *l;
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.transaction );
    l = SQRL_TRANSACTION_LIST;
    while( l ) {
        if( l->transaction == this ) {
            sqrl_mutex_enter( this->mutex );
            this->referenceCount++;
            sqrl_mutex_leave( this->mutex );
            break;
        }
        l = l->next;
    }
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.transaction );
}

SqrlTransaction *SqrlTransaction::release()
{
	bool freeMe = false;
    struct Sqrl_Transaction_List *l = NULL, *n = NULL;
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.transaction );
    n = SQRL_TRANSACTION_LIST;
    while( n ) {
        if( n->transaction == this ) {
            sqrl_mutex_enter( this->mutex );
            this->referenceCount--;
            if( this->referenceCount < 1 ) {
                if( l ) l->next = n->next;
                else SQRL_TRANSACTION_LIST = n->next;
                free( n );
                freeMe = true;
            }
            sqrl_mutex_leave( this->mutex );
            break;
        }
        l = n;
        n = l->next;
    }
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.transaction );
    if( freeMe ) {
		if (this->user) {
			this->user->release();
		}
		if (this->uri) this->uri = this->uri->release();
        if( this->string ) free( this->string );
        if( this->altIdentity ) free( this->altIdentity );
        // free ->data
        sqrl_mutex_destroy( this->mutex );
        free( this );
    }
	return NULL;
}

void SqrlTransaction::setUser( SqrlUser *u )
{
    if( !u ) return;
	if (this->user) {
		this->user->release();
	}
	this->user = u;
	u->hold();
}

Sqrl_Transaction_Status SqrlTransaction::getStatus()
{
	return this->status;
}

void SqrlTransaction::setStatus(Sqrl_Transaction_Status status)
{
	this->status = status;
}

Sqrl_Export SqrlTransaction::getExportType()
{
	return this->exportType;
}

void SqrlTransaction::setExportType(Sqrl_Export type)
{
	this->exportType = type;
}

Sqrl_Encoding SqrlTransaction::getEncodingType()
{
	return this->encodingType;
}

void SqrlTransaction::setEncodingType(Sqrl_Encoding type)
{
	this->encodingType = type;
}

Sqrl_Transaction_Type SqrlTransaction::getType()
{
	return this->type;
}

SqrlUser *SqrlTransaction::getUser()
{
	return this->user;
}

char *SqrlTransaction::getAltIdentity()
{
	return this->altIdentity;
}

void SqrlTransaction::setAltIdentity(const char *alt)
{
	if (this->altIdentity) {
		free(this->altIdentity);
		this->altIdentity = NULL;
	}
	if (alt) {
		size_t len = strlen( alt ) + 1;
		this->altIdentity = (char*)malloc(len);
		strcpy_s(this->altIdentity, len, alt);
	}
}

SqrlUri *SqrlTransaction::getUri()
{
	return this->uri;
}

void SqrlTransaction::setUri(SqrlUri *uri)
{
	if (this->uri) {
		this->uri = this->uri->release();
	}
	this->uri = uri->copy();
}

/**
Gets a string from a \p Sqrl_Transaction.  Typically used to retrieve
the result of a \p sqrl_client_export_user() during the 
\p sqrl_ccb_transaction_complete callback.

@param transaction The \p Sqrl_Transaction
@param buf A string buffer to hold the result.  If NULL, returns size of string only.
@param len Pointer to \p size_t containing the length of \p buf.  If buf is not NULL, modified to contain length of string.
@return \p size_t Length of the \p Sqrl_Transaction's string
*/

size_t SqrlTransaction::getString( char *buf, size_t *len )
{
    size_t retVal = this->string_len;
    if( this->string ) {
        if( buf && len && *len ) {
            if( retVal < *len ) {
                memcpy( buf, this->string, retVal );
                buf[retVal] = 0;
                *len = retVal;
            } else {
                memcpy( buf, this->string, *len );
            }
        }
    }
    return retVal;
}

void SqrlTransaction::setString(char *buf, size_t len)
{
	if (this->string) {
		free(this->string);
	}
	this->string = NULL;
	this->string_len = 0;
	if (buf && len > 0) {
		this->string = (char*)malloc(len + 1);
		memcpy(this->string, buf, len);
		this->string[len] = 0;
		this->string_len = len;
	}
}

