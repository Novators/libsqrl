/** @file transaction.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#include "sqrl_internal.h"
#include "sqrl.h"
#include "SqrlAction.h"
#include "SqrlUri.h"
#include "SqrlUser.h"

struct Sqrl_Transaction_List {
	SqrlAction *transaction;
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

SqrlAction::SqrlAction()
: user(NULL),
  uri(NULL),
  referenceCount(1),
  runState(0),
  finished(false),
  running(false) {
	struct Sqrl_Transaction_List *list = (struct Sqrl_Transaction_List*)calloc( 1, sizeof( struct Sqrl_Transaction_List ) );
	this->mutex = sqrl_mutex_create();
	list->transaction = this;
	sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.transaction );
	list->next = SQRL_TRANSACTION_LIST;
	SQRL_TRANSACTION_LIST = list;
	sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.transaction );
}

int SqrlAction::countTransactions()
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

void SqrlAction::hold()
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

SqrlAction *SqrlAction::release()
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
		this->onRelease();
		if( this->user ) {
			this->user->release();
		}
		if( this->uri ) this->uri = this->uri->release();
		sqrl_mutex_destroy( this->mutex );
		free( this );
	}
	return NULL;
}

void SqrlAction::onRelease() {
}

bool SqrlAction::isFinished() {
	return this->finished;
}

void SqrlAction::setUser( SqrlUser *u )
{
    if( !u ) return;
	if (this->user) {
		this->user->release();
	}
	this->user = u;
	u->hold();
}

SqrlUser *SqrlAction::getUser()
{
	return this->user;
}

SqrlUri *SqrlAction::getUri()
{
	return this->uri;
}

void SqrlAction::setUri(SqrlUri *uri)
{
	if (this->uri) {
		this->uri = this->uri->release();
	}
	this->uri = uri->copy();
}

void SqrlAction::authenticate( Sqrl_Credential_Type credentialType, const char *credential, size_t length ) {
	if( !this->user ) return;
	switch( credentialType ) {
	case SQRL_CREDENTIAL_HINT:
		break;
	case SQRL_CREDENTIAL_PASSWORD:
		break;
	case SQRL_CREDENTIAL_NEW_PASSWORD:
		this->user->setPassword( credential, length );
		break;
	case SQRL_CREDENTIAL_RESCUE_CODE:
		break;
	}
}
