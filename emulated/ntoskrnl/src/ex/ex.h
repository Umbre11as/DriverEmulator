#pragma once

#include "../keprocess.h"

BOOLEAN ExfAcquireRundownProtection(IN PEX_RUNDOWN_REF RunRef);
void ExfReleaseRundownProtection(IN PEX_RUNDOWN_REF RunRef);

EXPORT BOOLEAN ExAcquireRundownProtection(IN PEX_RUNDOWN_REF RunRef);
EXPORT void ExReleaseRundownProtection(IN PEX_RUNDOWN_REF RunRef);

typedef LONG KPRIORITY, *PKPRIORITY;
