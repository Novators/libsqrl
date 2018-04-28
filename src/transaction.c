/** @file transaction.c 

@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
*/
#include <stdlib.h>
#include <stdio.h>
#include "sqrl_internal.h"

struct Sqrl_Transaction_List *SQRL_TRANSACTION_LIST = NULL;

Sqrl_Transaction sqrl_transaction_create( Sqrl_Transaction_Type type )
{
    struct Sqrl_Transaction *transaction = calloc( 1, sizeof( struct Sqrl_Transaction ));
    struct Sqrl_Transaction_List *list = calloc( 1, sizeof( struct Sqrl_Transaction_List ));
    transaction->type = type;
    transaction->referenceCount = 1;
    transaction->mutex = sqrl_mutex_create();
    list->transaction = transaction;
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.transaction );
    list->next = SQRL_TRANSACTION_LIST;
    SQRL_TRANSACTION_LIST = list;
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.transaction );
    return (Sqrl_Transaction)transaction;
}

int sqrl_transaction_count()
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

Sqrl_Transaction sqrl_transaction_hold( Sqrl_Transaction t )
{
    SQRL_CAST_TRANSACTION(transaction,t);
    if( !transaction ) return NULL;
    struct Sqrl_Transaction_List *l;
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.transaction );
    l = SQRL_TRANSACTION_LIST;
    while( l ) {
        if( l->transaction == transaction ) {
            sqrl_mutex_enter( transaction->mutex );
            transaction->referenceCount++;
#if DEBUG_PRINT_TRANSACTION_COUNT==1
			printf( "sqrl_transaction_hold: %d\n", transaction->referenceCount );
#endif
            sqrl_mutex_leave( transaction->mutex );
            break;
        }
        l = l->next;
    }
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.transaction );
    return (Sqrl_Transaction)transaction;
}

Sqrl_Transaction sqrl_transaction_release( Sqrl_Transaction t )
{
    SQRL_CAST_TRANSACTION(transaction,t);
    if( transaction == NULL ) return NULL;
    struct Sqrl_Transaction *freeMe = NULL;
    struct Sqrl_Transaction_List *l = NULL, *n = NULL;
    sqrl_mutex_enter( SQRL_GLOBAL_MUTICES.transaction );
    n = SQRL_TRANSACTION_LIST;
    while( n ) {
        if( n->transaction == transaction ) {
            sqrl_mutex_enter( transaction->mutex );
            transaction->referenceCount--;
#if DEBUG_PRINT_TRANSACTION_COUNT==1
			printf( "sqrl_transaction_release: %d\n", transaction->referenceCount );
#endif
            if( transaction->referenceCount < 1 ) {
                if( l ) l->next = n->next;
                else SQRL_TRANSACTION_LIST = n->next;
                free( n );
                freeMe = transaction;
            }
            sqrl_mutex_leave( transaction->mutex );
            break;
        }
        l = n;
        n = l->next;
    }
    sqrl_mutex_leave( SQRL_GLOBAL_MUTICES.transaction );
    if( freeMe ) {
        freeMe->user = sqrl_user_release( freeMe->user );
        freeMe->uri = sqrl_uri_free( freeMe->uri );
        if( freeMe->string ) free( freeMe->string );
        if( freeMe->altIdentity ) free( freeMe->altIdentity );
        // free ->data
        sqrl_mutex_destroy( freeMe->mutex );
        free( freeMe );
    }
    return NULL;
}

int sqrl_transactions_with_user( Sqrl_User u ) {
	int retval = 0;
	struct Sqrl_Transaction_List *l = SQRL_TRANSACTION_LIST;
	while( l ) {
		if( l->transaction->user == u ) retval++;
		l = l->next;
	}
	return retval;
}

void sqrl_transaction_set_user( Sqrl_Transaction t, Sqrl_User u )
{
    if( !u ) return;
    WITH_TRANSACTION(transaction,t);
    if( !transaction ) {
        return;
    }
    if( transaction->user != u ) {
		Sqrl_User ou = transaction->user;
		transaction->user = sqrl_user_hold( u );
		if( ou ) {
			sqrl_user_release( ou );
		}
	}
    END_WITH_TRANSACTION(transaction);
}

/**
Gets the current \p Sqrl_Transaction_Status of a \p Sqrl_Transaction

@param transaction the \p Sqrl_Transaction
@return \p Sqrl_Transaction_Status
*/
DLL_PUBLIC
Sqrl_Transaction_Status sqrl_transaction_status( Sqrl_Transaction t )
{
    Sqrl_Transaction_Status status = SQRL_TRANSACTION_STATUS_FAILED;
    SQRL_CAST_TRANSACTION(transaction,t);
    if( transaction ) status = transaction->status;
    return status;
}

/**
Gets the \p Sqrl_Transaction_Type of a \p Sqrl_Transaction

@param transaction the \p Sqrl_Transaction
@return \p Sqrl_Transaction_Type
*/
DLL_PUBLIC
Sqrl_Transaction_Type sqrl_transaction_type( Sqrl_Transaction t )
{
    Sqrl_Transaction_Type type = SQRL_TRANSACTION_UNKNOWN;
    SQRL_CAST_TRANSACTION(transaction,t);
    if( transaction ) type = transaction->type;
    return type;
}

/**
Gets the \p Sqrl_User associated with a \p Sqrl_Transaction

@param transaction the \p Sqrl_Transaction
@return \p Sqrl_User the associated user
@return NULL A \p Sqrl_User is not associated with this transaction
*/
DLL_PUBLIC
Sqrl_User sqrl_transaction_user( Sqrl_Transaction t )
{
    Sqrl_User user = NULL;
    SQRL_CAST_TRANSACTION(transaction,t);
    if( transaction ) user = transaction->user;
    return user;
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
DLL_PUBLIC
size_t sqrl_transaction_string( Sqrl_Transaction t, char *buf, size_t *len )
{
    WITH_TRANSACTION(transaction,t);
    size_t retVal = transaction->string_len;
    if( transaction->string ) {
        if( buf && len && *len ) {
            if( retVal < *len ) {
                memcpy( buf, transaction->string, retVal );
                buf[retVal] = 0;
                *len = retVal;
            } else {
                memcpy( buf, transaction->string, *len );
            }
        }
    }
    END_WITH_TRANSACTION(transaction);
    return retVal;
}
