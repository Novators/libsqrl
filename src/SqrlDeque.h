/** @file SqrlDeque.h
@author Adam Comley

This file is part of libsqrl.  It is released under the MIT license.
For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLDEQUE_H
#define SQRLDEQUE_H

template <class T>
class DLL_PUBLIC SqrlDeque
{
private:
	template <class T2>
	struct item
	{
		item( T2 newItem ) {
			this->myItem = newItem;
			this->next = NULL;
		}
		T2 myItem;
		item *next;
	};
	struct item<T> *list;

public:
	SqrlDeque() {
		this->list = NULL;
	}

	~SqrlDeque() {
		if( this->list ) delete this->list;
	}

	void push( T newItem ) {
		struct item<T> *newStruct = new struct item<T>( newItem );
		newStruct->next = this->list;
		this->list = newStruct;
	}

	void push_back( T newItem ) {
		struct item<T> *newStruct = new struct item<T>( newItem );
		if( !this->list ) {
			this->list = newStruct;
			return;
		}
		struct item<T> *cur = this->list;
		while( cur->next ) {
			cur = cur->next;
		}
		cur->next = newStruct;
	}

	T pop() {
		if( !this->list ) return NULL;
		struct item<T> *freeMe = this->list;
		T ret = freeMe->myItem;
		this->list = freeMe->next;
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


	T pop_back() {
		if( !this->list ) return NULL;
		if( this->list->next == NULL ) {
			return this->pop();
		}
		struct item<T> *cur = this->list;
		while( cur->next && cur->next->next ) {
			cur = cur->next;
		}
		struct item<T> *freeMe = cur->next;
		T ret = freeMe->myItem;
		cur->next = NULL;
		delete freeMe;
		return ret;
	}

	T peek() {
		if( !this->list ) return NULL;
		return this->list->myItem;
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

#endif // SQRLDEQUE_H
