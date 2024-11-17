#include <Windows.h>
#include <ntstatus.h>

#define EXPORT __declspec(dllexport)

typedef PVOID PEX_RUNDOWN_REF;

extern void ExReleaseRundownProtection(IN PEX_RUNDOWN_REF RunRef);
extern BOOLEAN ExAcquireRundownProtection(IN PEX_RUNDOWN_REF RunRef);

EXPORT void FltObjectDereference(IN OUT PVOID FltObject) {
    return ExReleaseRundownProtection((PEX_RUNDOWN_REF) ((ULONGLONG) FltObject + 1));
}

EXPORT NTSTATUS FltObjectReference(IN PVOID FltObject) {
    if (ExAcquireRundownProtection((PEX_RUNDOWN_REF) ((ULONGLONG) FltObject + 1)))
        return STATUS_SUCCESS;

    return STATUS_FLT_DELETING_OBJECT;
}
