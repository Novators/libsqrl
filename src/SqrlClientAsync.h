#pragma once

#include "sqrl.h"
#include "SqrlClient.h"
#include <queue>

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
