#include "ex.h"

#include "io.c"

BOOLEAN ExfAcquireRundownProtection(IN PEX_RUNDOWN_REF RunRef) {
    _m_prefetchw(RunRef);

    LONGLONG Count = RunRef->Count;
    if ((RunRef->Count & 1) != 0)
        return FALSE;

    while (TRUE) {
        LONGLONG temp = Count;
        Count = _InterlockedCompareExchange64((volatile LONGLONG*) RunRef, Count + 2, Count);
        if (temp == Count)
            break;

        if ((Count & 1) != 0)
            return FALSE;
    }

    return TRUE;
}

EXPORT BOOLEAN ExAcquireRundownProtection(IN PEX_RUNDOWN_REF RunRef) {
    _m_prefetchw(RunRef);
    LONGLONG count = RunRef->Count & 0xFFFFFFFFFFFFFFFEu;
    if (count == _InterlockedCompareExchange64((volatile LONGLONG*) RunRef, count + 2, count))
        return TRUE;

    return ExfAcquireRundownProtection(RunRef);
}

void ExfReleaseRundownProtection(IN PEX_RUNDOWN_REF RunRef) {
    _m_prefetchw(RunRef);
    ULONGLONG Count = RunRef->Count;
    if ((RunRef->Count & 1) != 0) {
        ULONGLONG count = 0;

        recalcCount:
            count = Count & 0xFFFFFFFFFFFFFFFEui64;
        if (_InterlockedExchangeAdd64((volatile LONGLONG*) count, 0xFFFFFFFFFFFFFFFFu) == 1 && !_interlockedbittestandreset((volatile LONG*)(count + 32), 0))
            KeSetEvent((PRKEVENT)(count + 8), 0, 0);
    } else {
        while (TRUE) {
            LONGLONG newCount = _InterlockedCompareExchange64((volatile LONGLONG*) RunRef, Count - 2, Count);
            BOOLEAN isSame = Count == newCount;
            Count = newCount;
            if (isSame)
                break;

            if ((newCount & 1) != 0)
                goto recalcCount;
        }
    }
}

EXPORT void ExReleaseRundownProtection(IN PEX_RUNDOWN_REF RunRef) {
    _m_prefetchw(RunRef);
    ULONGLONG count = RunRef->Count & 0xFFFFFFFFFFFFFFFEu;
    if (count != _InterlockedCompareExchange64((volatile LONGLONG*) RunRef, count - 2, count))
        ExfReleaseRundownProtection(RunRef);
}
