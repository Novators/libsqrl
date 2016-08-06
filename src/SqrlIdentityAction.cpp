/** \file SqrlIdentityAction.cpp
 *
 * \author Adam Comley
 *
 * This file is part of libsqrl.  It is released under the MIT license.
 * For more details, see the LICENSE file included with this package.
**/

#include "sqrl_internal.h"
#include "SqrlIdentityAction.h"

SqrlIdentityAction::SqrlIdentityAction( SqrlUser *user ) : SqrlAction() {
	this->setUser( user );
}

void SqrlIdentityAction::onRelease() {
	SqrlAction::onRelease();
}
