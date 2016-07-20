#include "sqrl_internal.h"
#include "SqrlIdentityAction.h"

SqrlIdentityAction::SqrlIdentityAction( SqrlUser *user ) : SqrlAction() {
	this->setUser( user );
}

void SqrlIdentityAction::onRelease() {
	SqrlAction::onRelease();
}
