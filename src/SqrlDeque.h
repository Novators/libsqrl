/** \file SqrlDeque.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLDEQUE_H
#define SQRLDEQUE_H

namespace libsqrl
{
    template <class T>
    class DLL_PUBLIC SqrlDeque
    {
    private:
        template <class T2>
        struct item
        {
            item( T2 newItem ) {
                this->myItem = newItem;
                this->previous = NULL;
                this->next = NULL;
            }
            T2 myItem;
            item *previous;
            item *next;
        };
        struct item<T> *list;
        struct item<T> *lend;

    public:
        SqrlDeque() {
            this->list = NULL;
            this->lend = NULL;
        }

        ~SqrlDeque() {
            struct item<T> *cur = this->list;
            struct item<T> *nxt = NULL;
            while( cur ) {
                nxt = cur->next;
                delete cur;
                cur = nxt;
            }
        }

        void push( T newItem ) {
            struct item<T> *newStruct = new struct item<T>( newItem );
            newStruct->next = this->list;
            if( this->list ) {
                this->list->previous = newStruct;
            } else {
                this->lend = newStruct;
            }
            this->list = newStruct;
        }

        void push_back( T newItem ) {
            struct item<T> *newStruct = new struct item<T>( newItem );
            newStruct->previous = this->lend;
            if( this->lend ) {
                this->lend->next = newStruct;
            } else {
                this->list = newStruct;
            }
            this->lend = newStruct;
        }

        T pop() {
            if( !this->list ) return NULL;
            struct item<T> *freeMe = this->list;
            T ret = freeMe->myItem;
            if( freeMe->next ) {
                freeMe->next->previous = NULL;
            } else {
                this->lend = NULL;
            }
            this->list = freeMe->next;
            delete freeMe;
            return ret;
        }

        T pop_back() {
            if( !this->lend ) return NULL;
            struct item<T> *freeMe = this->lend;
            T ret = freeMe->myItem;
            if( freeMe->previous ) {
                freeMe->previous->next = NULL;
                this->lend = freeMe->previous;
            } else {
                this->list = NULL;
            }
            this->lend = freeMe->previous;
            delete freeMe;
            return ret;
        }

        void erase( T comp ) {
            if( !this->list ) return;
            struct item<T> *prev = NULL;
            struct item<T> *cur = this->list;
            struct item<T> *freeMe = NULL;
            while( cur ) {
                if( cur->myItem == comp ) {
                    freeMe = cur;
                    if( cur->next ) {
                        cur->next->previous = prev;
                    } else {
                        this->lend = prev;
                    }
                    if( prev ) {
                        prev->next = cur->next;
                        cur = cur->next;
                    } else {
                        this->list = cur->next;
                        cur = cur->next;
                    }
                    delete freeMe;
                    continue;
                } else {
                    prev = cur;
                    cur = cur->next;
                }
            }
        }


        T peek( size_t offset = 0 ) {
            if( !this->list ) return NULL;
            size_t cnt = 0;
            struct item<T> *cur = this->list;
            while( cur ) {
                if( cnt == offset ) {
                    return cur->myItem;
                }
                cur = cur->next;
                cnt++;
            }
            return NULL;
        }

        T peek_back() {
            if( !this->lend ) return NULL;
            return this->lend->myItem;
        }

        bool empty() {
            if( this->list ) return false;
            return true;
        }

        size_t count() {
            size_t ret = 0;
            struct item<T> *cur = this->list;
            while( cur ) {
                ret++;
                cur = cur->next;
            }
            return ret;
        }

    };
}
#endif // SQRLDEQUE_H
