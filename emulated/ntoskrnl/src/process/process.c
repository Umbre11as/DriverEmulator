#include "process.h"

#include "../allocator/allocator.h"
#include "../ntdll/wrapper.h"

EXPORT PCSTR PsGetProcessImageFileName(IN PEPROCESS Process) {
    return Process->ImageFileName;
}

EXPORT HANDLE PsGetProcessId(IN PEPROCESS Process) {
    return Process->UniqueProcessId;
}

EXPORT HANDLE PsGetCurrentProcessId() {
    return UlongToHandle(GetCurrentProcessId());
}

PVOID GetProcessHandleFromPID(IN DWORD pid) {
    PVOID process = NULL;

    ULONG size = 0;
    ZwQuerySystemInformation(SystemHandleInformation, NULL, size, &size);
    if (size <= 0)
        return process;

    PSYSTEM_HANDLE_INFORMATION handleInformation = ExAllocatePool(NonPagedPool, size);
    ZwQuerySystemInformation(SystemHandleInformation, handleInformation, size, &size);
    if (handleInformation == NULL)
        return process;

    for (ULONG i = 0; i < handleInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInformation->Handles[i];
        if (handle.UniqueProcessId == pid && handle.ObjectTypeIndex == 7)
            return handle.Object;
    }

    ExFreePool(handleInformation);
    return process;
}

EXPORT NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId, OUT PEPROCESS* Process) {
    DWORD pid = HandleToULong(ProcessId);
    PVOID systemProcessHandle = GetProcessHandleFromPID(4);
    if (systemProcessHandle == NULL)
        return STATUS_NOT_FOUND;

    return STATUS_SUCCESS;
}

EXPORT PVOID PsGetProcessSectionBaseAddress(IN PEPROCESS Process) {
    return Process->SectionBaseAddress;
}

EXPORT HANDLE PsGetCurrentProcessWin32Process() {
    return GetCurrentProcess();
}
