#pragma once

#include "SqrlTransaction.fwd.h"
#include "SqrlUser.fwd.h"

class DLL_PUBLIC SqrlTransaction
{
public:
	SqrlTransaction(Sqrl_Transaction_Type type);

	void hold();
	void release();
	void setUser(SqrlUser *user);
	SqrlUser* getUser();
	Sqrl_Transaction_Status getStatus();
	void setStatus(Sqrl_Transaction_Status status);
	Sqrl_Transaction_Type getType();
	size_t getString(char *buf, size_t *len);
	void setString(char *buf, size_t len);
	static int countTransactions();
	char *getAltIdentity();
	void setAltIdentity(const char *alt);
	SqrlUri *getUri();
	void setUri(SqrlUri *uri);
	Sqrl_Export getExportType();
	void setExportType(Sqrl_Export type);
	Sqrl_Encoding getEncodingType();
	void setEncodingType(Sqrl_Encoding type);

private:
	Sqrl_Transaction_Type type;
	SqrlUser *user;
	SqrlUri *uri;
	char *string;
	size_t string_len;
	Sqrl_Transaction_Status status;
	char *altIdentity;
	Sqrl_Export exportType;
	Sqrl_Encoding encodingType;
	void *data;
	SqrlMutex mutex;
	int referenceCount;
};

