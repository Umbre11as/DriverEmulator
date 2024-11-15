// ReSharper disable CppParameterNeverUsed
// ReSharper disable CppUnusedIncludeDirective
#include "ntdll/wrapper.h"
#include "dbg/dbg.h"
#include "allocator/allocator.h"
#include "mdl/mdl.h"
#include "thread/thread.h"
#include "process/process.h"

PVOID LastCheckAddress = NULL;
BOOLEAN BadAddressCheck = FALSE;

LONG NTAPI VEHandler(IN PEXCEPTION_POINTERS ExceptionInfo) {
    PEXCEPTION_RECORD record = ExceptionInfo->ExceptionRecord;
    if (record->ExceptionCode == STATUS_ACCESS_VIOLATION && record->ExceptionAddress == LastCheckAddress) {
        BadAddressCheck = TRUE;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ReSharper disable CppDFAUnreadVariable
// ReSharper disable CppDFAConstantFunctionResult
// ReSharper disable CppDFAUnreachableCode
// ReSharper disable CppDFAUnusedValue
// ReSharper disable CppDeclaratorNeverUsed
EXPORT BOOLEAN MmIsAddressValid(IN PVOID VirtualAddress) {
    LastCheckAddress = VirtualAddress;

    BYTE unused = *(BYTE*)VirtualAddress;
    const BOOLEAN result = BadAddressCheck;

    BadAddressCheck = FALSE;
    return result;
}
// ReSharper restore CppDeclaratorNeverUsed
// ReSharper restore CppDFAUnusedValue
// ReSharper restore CppDFAUnreachableCode
// ReSharper restore CppDFAConstantFunctionResult
// ReSharper restore CppDFAUnreadVariable

void GetSystemProcess(OUT PSYSTEM_PROCESS_INFORMATION SystemProcess) {
    ULONG size = 0;
    ZwQuerySystemInformation(SystemProcessInformation, NULL, size, &size);
    if (size <= 0)
        return;

    PSYSTEM_PROCESS_INFORMATION processInformation = ExAllocatePool(NonPagedPool, size);
    ZwQuerySystemInformation(SystemProcessInformation, processInformation, size, &size);
    if (processInformation == NULL)
        return;

    while (TRUE) {
        if (processInformation->NextEntryOffset == 0)
            break;

        if (processInformation->ImageName.Buffer && wcscmp(processInformation->ImageName.Buffer, L"System") == 0) {
            *SystemProcess = *processInformation;
            break;
        }

        processInformation = (PSYSTEM_PROCESS_INFORMATION) ((PBYTE) processInformation + processInformation->NextEntryOffset);
    }

    ExFreePool(processInformation);
}

PCSTR ConvertToAscii(IN PWCH UnicodeName) {
    int length = WideCharToMultiByte(CP_UTF8, 0, UnicodeName, -1, NULL, 0, NULL, NULL);
    char* string = malloc(length + 1);
    WideCharToMultiByte(CP_UTF8, 0, UnicodeName, -1, string, lstrlenW(UnicodeName), NULL, NULL);
    string[length] = '\0';

    return string;
}

BOOL WINAPI DllMain(IN HINSTANCE InstanceHandle, IN DWORD Reason, IN PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH)
        AddVectoredExceptionHandler(1, VEHandler);

    SYSTEM_PROCESS_INFORMATION systemProcess;
    GetSystemProcess(&systemProcess);

    PsInitialSystemProcess = malloc(sizeof(EPROCESS));
    memcpy(PsInitialSystemProcess->ImageFileName, ConvertToAscii(systemProcess.ImageName.Buffer), systemProcess.ImageName.Length);

    return TRUE;
}
