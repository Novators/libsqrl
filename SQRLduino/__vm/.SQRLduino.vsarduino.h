/* 
	Editor: http://www.visualmicro.com
	        visual micro and the arduino ide ignore this code during compilation. this code is automatically maintained by visualmicro, manual changes to this file will be overwritten
	        the contents of the Visual Micro sketch sub folder can be deleted prior to publishing a project
	        all non-arduino files created by visual micro and all visual studio project or solution files can be freely deleted and are not required to compile a sketch (do not delete your own code!).
	        note: debugger breakpoints are stored in '.sln' or '.asln' files, knowledge of last uploaded breakpoints is stored in the upload.vmps.xml file. Both files are required to continue a previous debug session without needing to compile and upload again
	
	Hardware: Teensy 3.2 / 3.1, Platform=teensy3, Package=teensy
*/

#ifndef _VSARDUINO_H_
#define _VSARDUINO_H_
#define __HARDWARE_MK20dx256__
#define __HARDWARE_MK20DX256__
#define __MK20DX256__
#define TEENSYDUINO 129
#define ARDUINO 10609
#define F_CPU {build.fcpu}
#define {build.usbtype}
#define LAYOUT_{build.keylayout}
#define __cplusplus 201103L
#define __arm__
#define __ARM__
#define __extension__
#define  __attribute__(x)
typedef void *__builtin_va_list;
#define __extension__
#define __ATTR_PURE__
#define __ATTR_CONST__
#define __inline__
#define __asm__ 
#define __volatile__
#define _HAVE_STDC

#define NEW_H

#include <arduino.h>
#define __arm__
#define __ARM__
#define __extension__
#define  __attribute__(x)
typedef void *__builtin_va_list;
#define __extension__
#define __ATTR_PURE__
#define __ATTR_CONST__
#define __inline__
#define __asm__ 
#define __volatile__

#define __disable_irq() __asm__ volatile("");
#define __enable_irq()	__asm__ volatile("");


#define NEW_H
#include <SQRLduino.ino>
#include <QueueList.h>
#include <..\src\SqrlAction.cpp>
#include <..\src\SqrlAction.h>
#include <..\src\SqrlActionChangePassword.cpp>
#include <..\src\SqrlActionChangePassword.h>
#include <..\src\SqrlActionDisable.cpp>
#include <..\src\SqrlActionDisable.h>
#include <..\src\SqrlActionEnable.cpp>
#include <..\src\SqrlActionEnable.h>
#include <..\src\SqrlActionGenerate.cpp>
#include <..\src\SqrlActionGenerate.h>
#include <..\src\SqrlActionIdent.cpp>
#include <..\src\SqrlActionIdent.h>
#include <..\src\SqrlActionLock.cpp>
#include <..\src\SqrlActionLock.h>
#include <..\src\SqrlActionRekey.cpp>
#include <..\src\SqrlActionRekey.h>
#include <..\src\SqrlActionRemove.cpp>
#include <..\src\SqrlActionRemove.h>
#include <..\src\SqrlActionRescue.cpp>
#include <..\src\SqrlActionRescue.h>
#include <..\src\SqrlActionSave.cpp>
#include <..\src\SqrlActionSave.h>
#include <..\src\SqrlBase64.cpp>
#include <..\src\SqrlBase64.h>
#include <..\src\SqrlBlock.cpp>
#include <..\src\SqrlBlock.h>
#include <..\src\SqrlClient.cpp>
#include <..\src\SqrlClient.h>
#include <..\src\SqrlClientAsync.cpp>
#include <..\src\SqrlClientAsync.h>
#include <..\src\SqrlCrypt.cpp>
#include <..\src\SqrlCrypt.h>
#include <..\src\SqrlEncoder.h>
#include <..\src\SqrlEntropy.cpp>
#include <..\src\SqrlEntropy.h>
#include <..\src\SqrlEntropy_Arduino.h>
#include <..\src\SqrlEntropy_Linux.h>
#include <..\src\SqrlEntropy_Mac.h>
#include <..\src\SqrlEntropy_Win.h>
#include <..\src\SqrlForwardDeclarations.h>
#include <..\src\SqrlIdentityAction.cpp>
#include <..\src\SqrlIdentityAction.h>
#include <..\src\SqrlServer.cpp>
#include <..\src\SqrlServer.h>
#include <..\src\SqrlSiteAction.cpp>
#include <..\src\SqrlSiteAction.h>
#include <..\src\SqrlStorage.cpp>
#include <..\src\SqrlStorage.h>
#include <..\src\SqrlUri.cpp>
#include <..\src\SqrlUri.h>
#include <..\src\SqrlUrlEncode.cpp>
#include <..\src\SqrlUrlEncode.h>
#include <..\src\SqrlUser.cpp>
#include <..\src\SqrlUser.h>
#include <..\src\SqrlUser_storage.cpp>
#include <..\src\aes.cpp>
#include <..\src\aes.h>
#include <..\src\config.h>
#include <..\src\detect_platform.h>
#include <..\src\gcm.cpp>
#include <..\src\gcm.h>
#include <..\src\platform.cpp>
#include <..\src\rdrand.h>
#include <..\src\sqrl.h>
#include <..\src\sqrl_internal.h>
#include <..\src\sqrl_server.h>
#include <..\src\util.cpp>
#include <..\src\version.h>
#endif
