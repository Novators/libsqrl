/** \file SqrlClientAsync.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLCLIENTASYNC_H
#define SQRLCLIENTASYNC_H

#include "sqrl.h"
#include "SqrlClient.h"

namespace libsqrl
{
	class DLL_PUBLIC SqrlClientAsync : public SqrlClient
	{
	public:
		SqrlClientAsync();
		~SqrlClientAsync();

	protected:

	private:
		static void clientThread();
		std::thread *myThread;
		bool stopping = false;

	};
}
#endif // SQRLCLIENTASYNC_H
