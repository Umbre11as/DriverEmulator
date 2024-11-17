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

void GetSystemModule(OUT PRTL_PROCESS_MODULE_INFORMATION SystemModule) {
    ULONG size = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, size, &size);
    if (size <= 0)
        return;

    PRTL_PROCESS_MODULES processModules = ExAllocatePool(NonPagedPool, size);
    ZwQuerySystemInformation(SystemModuleInformation, processModules, size, &size);
    if (processModules == NULL)
        return;

    for (ULONG i = 0; i < processModules->NumberOfModules; i++) {
        RTL_PROCESS_MODULE_INFORMATION moduleInformation = processModules->Modules[i];
        *SystemModule = moduleInformation;
    }

    ExFreePool(processModules);
}

PCSTR ConvertToAscii(IN PWCH UnicodeName) {
    int length = WideCharToMultiByte(CP_UTF8, 0, UnicodeName, -1, NULL, 0, NULL, NULL);
    char* string = malloc(length + 1);
    WideCharToMultiByte(CP_UTF8, 0, UnicodeName, -1, string, lstrlenW(UnicodeName), NULL, NULL);
    string[length] = '\0';

    return string;
}

struct _LIST_ENTRY DoubleLinkedProcesses() {
    struct _LIST_ENTRY root;
    root.Blink = NULL;

    ULONG size = 0;
    ZwQuerySystemInformation(SystemProcessInformation, NULL, size, &size);
    if (size <= 0)
        return root;

    PSYSTEM_PROCESS_INFORMATION processInformation = ExAllocatePool(NonPagedPool, size);
    ZwQuerySystemInformation(SystemProcessInformation, processInformation, size, &size);
    if (processInformation == NULL)
        return root;

    struct _LIST_ENTRY* current = &root;

    while (TRUE) {
        if (processInformation->NextEntryOffset == 0)
            break;

        DWORD pid = HandleToULong(processInformation->UniqueProcessId);
        if (pid == 0 || pid == 4) // Skip system processes (must last in list)
            goto next;

        // ReSharper disable CppDFAMemoryLeak
        // Where is no memory leaks, when dll is detached, we are cleaning process allocated memory
        PEPROCESS process = malloc(sizeof(EPROCESS));
        // ReSharper restore CppDFAMemoryLeak
        memcpy(process->ImageFileName, ConvertToAscii(processInformation->ImageName.Buffer), processInformation->ImageName.Length);

        current->Flink = (struct _LIST_ENTRY*) ((PCHAR) process + (ULONG_PTR)(&((PEPROCESS)0)->ActiveProcessLinks));
        current->Flink->Blink = current;
        current = current->Flink;

next:
        processInformation = (PSYSTEM_PROCESS_INFORMATION) ((PBYTE) processInformation + processInformation->NextEntryOffset);
    }

    current->Flink = (struct _LIST_ENTRY*) ((PCHAR) PsInitialSystemProcess + (ULONG_PTR)(&((PEPROCESS)0)->ActiveProcessLinks)); // Last process is system

    ExFreePool(processInformation);
    return root;
}

BOOL WINAPI DllMain(IN HINSTANCE InstanceHandle, IN DWORD Reason, IN PVOID Reserved) {
    switch (Reason) {
        case DLL_PROCESS_ATTACH: {
            SYSTEM_PROCESS_INFORMATION systemProcess;
            GetSystemProcess(&systemProcess);

            RTL_PROCESS_MODULE_INFORMATION moduleInformation;
            GetSystemModule(&moduleInformation);

            PsInitialSystemProcess = malloc(sizeof(EPROCESS));
            memcpy(PsInitialSystemProcess->ImageFileName, ConvertToAscii(systemProcess.ImageName.Buffer), systemProcess.ImageName.Length);
            PsInitialSystemProcess->UniqueProcessId = systemProcess.UniqueProcessId;
            PsInitialSystemProcess->CreateTime = systemProcess.CreateTime;
            PsInitialSystemProcess->ProcessQuotaUsage[PsPagedPool] = systemProcess.QuotaPagedPoolUsage;
            PsInitialSystemProcess->ProcessQuotaUsage[PsNonPagedPool] = systemProcess.QuotaNonPagedPoolUsage;
            PsInitialSystemProcess->ProcessQuotaPeak[PsPagedPool] = systemProcess.QuotaPeakPagedPoolUsage;
            PsInitialSystemProcess->ProcessQuotaPeak[PsNonPagedPool] = systemProcess.QuotaPeakNonPagedPoolUsage;
            PsInitialSystemProcess->PeakVirtualSize = systemProcess.PeakVirtualSize;
            PsInitialSystemProcess->VirtualSize = systemProcess.VirtualSize;
            PsInitialSystemProcess->SectionBaseAddress = moduleInformation.ImageBase;
            PsInitialSystemProcess->Win32Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, HandleToULong(PsInitialSystemProcess->UniqueProcessId));
            PsInitialSystemProcess->Peb = (struct _PEB*) __readgsqword(0x60); // :)

            PsInitialSystemProcess->ActiveProcessLinks = DoubleLinkedProcesses();
            AddVectoredExceptionHandler(1, VEHandler);
            break;
        }
        case DLL_PROCESS_DETACH: {
            for (PEPROCESS process = PsInitialSystemProcess; process != PsInitialSystemProcess; process = CONTAINING_RECORD(process->ActiveProcessLinks.Flink, EPROCESS, ActiveProcessLinks))
                free(process);

            free(PsInitialSystemProcess->ImageFileName);
            free(PsInitialSystemProcess);
            break;
        }
        default: break;
    }

    return TRUE;
}
