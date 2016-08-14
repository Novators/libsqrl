/*
 Name:		SQRLduino.ino
 Created:	8/2/2016 9:38:11 AM
 Author:	adam
 Editor:	http://www.visualmicro.com
*/

#include "SqrlString.h"
#include "SqrlClient.h"
#include "SqrlUser.h"

using namespace libsqrl;

class MyClient : public SqrlClient
{
    // Inherited via SqrlClient
    virtual void onSend( SqrlAction * t, SqrlString url, SqrlString payload ) override {
    }
    virtual void onProgress( SqrlAction * action, int progress ) override {
    }
    virtual void onAsk( SqrlAction * action, SqrlString message, SqrlString firstButton, SqrlString secondButton ) override {
    }
    virtual void onAuthenticationRequired( SqrlAction * action, Sqrl_Credential_Type credentialType ) override {
    }
    virtual void onSelectUser( SqrlAction * action ) override {
    }
    virtual void onSelectAlternateIdentity( SqrlAction * action ) override {
    }
    virtual void onSaveSuggested( SqrlUser * user ) override {
    }
    virtual void onActionComplete( SqrlAction * action ) override {
    }
};

MyClient theClient = MyClient();
SqrlUser theUser = SqrlUser();

// the setup function runs once when you press reset or power the board
void setup() {
    
}

// the loop function runs over and over again until power down or reset
void loop() {
    theClient.loop();
}
