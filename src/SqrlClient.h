/** \file SqrlClient.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLCLIENT_H
#define SQRLCLIENT_H

#include "sqrl.h"
#include "SqrlString.h"
#include "SqrlDeque.h"

namespace libsqrl
{
    class DLL_PUBLIC SqrlClient
    {
        friend class SqrlClientAsync;
        friend class SqrlAction;
        friend class SqrlUser;
        friend class SqrlActionSave;
        friend class SqrlActionGenerate;
        friend class SqrlActionRekey;
        friend class SqrlActionRescue;
        friend class SqrlActionLock;
        friend class SqrlActionChangePassword;

    public:
        SqrlClient();
        ~SqrlClient();
        static SqrlClient *getClient();
        bool loop();
		SqrlUser *getUser( const SqrlString *uniqueId );
		SqrlUser *getUser( void *tag );

    protected:
        bool rapid;

        virtual int getUserIdleSeconds();
        virtual bool isScreenLocked();
        virtual bool isUserChanged();

        virtual void onLoop();
        virtual void onSend(
            SqrlAction *t, SqrlString url, SqrlString payload ) = 0;
        virtual void onProgress(
            SqrlAction *action, int progress ) = 0;
        virtual void onAsk(
            SqrlAction *action,
            SqrlString message, SqrlString firstButton, SqrlString secondButton ) = 0;
        virtual void onAuthenticationRequired(
            SqrlAction *action, Sqrl_Credential_Type credentialType ) = 0;
        virtual void onSelectUser( SqrlAction *action ) = 0;
        virtual void onSelectAlternateIdentity(
            SqrlAction *action ) = 0;
        virtual void onSaveSuggested(
            SqrlUser *user ) = 0;
        virtual void onActionComplete(
            SqrlAction *action ) = 0;
		virtual void onClientIsStopping() {}

        struct CallbackInfo
        {
            CallbackInfo();
            ~CallbackInfo();

            int cbType;
            int progress;
            Sqrl_Credential_Type credentialType;
            void *ptr;
            SqrlString* str[3];
        };

    private:
		static SqrlClient *client;

        SqrlDeque<struct CallbackInfo*> callbackQueue;
        SqrlDeque<SqrlAction *>actions;
		SqrlDeque<SqrlUser*>users;
#if defined(WITH_THREADS)
		static std::mutex *clientMutex;
        std::mutex actionMutex;
        std::mutex userMutex;
#endif

        void callSaveSuggested(
            SqrlUser *user );
        void callSelectUser( SqrlAction *action );
        void callSelectAlternateIdentity(
            SqrlAction *action );
        void callActionComplete(
            SqrlAction *action );
        void callProgress(
            SqrlAction *action,
            int progress );
        void callAuthenticationRequired(
            SqrlAction *action,
            Sqrl_Credential_Type credentialType );
        void callSend(
            SqrlAction *t, SqrlString *url, SqrlString *payload );
        void callAsk(
            SqrlAction *action,
            SqrlString *message, SqrlString *firstButton, SqrlString *secondButton );

    };
}
#endif // SQRLCLIENT_H
