/** \file SqrlAction.h
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#ifndef SQRLACTION_H
#define SQRLACTION_H

#include <climits>
#include "sqrl.h"

namespace libsqrl
{

#define SQRL_ACTION_RUNNING 0
#define SQRL_ACTION_SUCCESS 1
#define SQRL_ACTION_FAIL -1
#define SQRL_ACTION_CANCELED -2

#define SQRL_ACTION_STATE_DELETE INT_MIN

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>An Action, typically initiated by the user and managed by the SqrlClient.</summary>
    ///
    /// <remarks>
    /// For Implementers:
    ///   - Children of SqrlAction must override the run() method, to process the requested action.
    ///
    /// For Consumers:
    ///   - Starting a new SqrlAction:
    ///     - Call '''new SqrlAction();''' to start a SqrlAction.  Disregard the pointer.
    ///     - Do not use SqrlActions as global or local variables.
    /// 	- Ending a SqrlAction:
    /// 	  - Do not attempt to delete a SqrlAction.  Instead, call SqrlAction::cancel(). It will
    /// 	    stop cleanly and be deleted by libsqrl.
    /// 	- Interacting with a SqrlAction:
    /// 	  - Once a SqrlAction is created, all further interaction with it will be through the
    /// 	    SqrlClient and it's callbacks.</remarks>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    class DLL_PUBLIC SqrlAction
    {
        friend class SqrlClient;
        friend class SqrlClientAsync;
        friend class SqrlUser;
        friend class SqrlIdentityAction;
        friend class SqrlCrypt;

    public:
        SqrlAction();

        /// <summary>	Cancels this action. </summary>
        void cancel();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Authenticates the user to libsqrl.</summary>
        ///
        /// <param name="credentialType">  Type of the credential.</param>
        /// <param name="credential">	   The credential.</param>
        /// <param name="credentialLength">Length of the credential.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        void authenticate( Sqrl_Credential_Type credentialType, const char *credential, size_t credentialLength );

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Gets the user.</summary>
        ///
        /// <returns>If a SqrlUser is associated with this SqrlAction, the user. Else, NULL.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlUser* getUser();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Associates a SqrlUser with this SqrlAction.  Call in response to
        /// SqrlClient::onSelectUser().</summary>
        ///
        /// <param name="user">[in,out] If non-null, the user.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        void setUser( SqrlUser *user );

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Gets the URI.</summary>
        ///
        /// <returns>URI associated with this SqrlAction, or null if none.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        SqrlUri *getUri();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Sets an URI.</summary>
        ///
        /// <param name="uri">[in,out] If non-null, URI to use in this SqrlAction.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        void setUri( SqrlUri *uri );

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets tag.</summary>
		///
		/// <returns>The tag, or NULL if not set.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void *getTag();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets a tag.</summary>
		///
		/// <param name="tag">[in] Sets the tag, or if NULL, unsets the tag.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void setTag( void *tag );
    protected:
        virtual ~SqrlAction();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Steps through this SqrlAction's state machine. Called by the SqrlClient.</summary>
        ///
        /// <remarks>
        /// This should complete the required action in a series of fast steps.  It should never block.
        /// We recommend using state machine logic within this function.</remarks>
        ///
        /// <param name="currentState">The current state.</param>
        ///
        /// <returns>The state that will be passed to SqrlAction::run() on the next step.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        virtual int run( int currentState ) = 0;

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Call from a SqrlAction's run() loop to indicate that the action is complete.</summary>
        ///
        /// <param name="status">The status of the action.</param>
        ///
        /// <returns>Return this value from your SqrlAction::run() loop.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        int retActionComplete( int status );

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Called from the SqrlClient to initiate a step of the state machine.</summary>
        ///
        /// <returns>true if action should continue, false if action is complete.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        bool exec();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Called when an action is about to be deleted, to clean up any memory allocations,
        /// etc...</summary>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        virtual void onRelease();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Called internally to update progress bar.</summary>
        ///
        /// <param name="progress">Progress of current operation (percentage between 0 and 100)</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        virtual void onProgress( int progress );

        SqrlUser *user;
        SqrlUri *uri;
		void *tag;
        int state;
        int status;
        bool shouldCancel;
    };
}
#endif // SQRLACTION_H
