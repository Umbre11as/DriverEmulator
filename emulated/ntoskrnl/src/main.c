// ReSharper disable CppParameterNeverUsed
// ReSharper disable CppUnusedIncludeDirective
#include "ntdll/wrapper.h"
#include "dbg/dbg.h"
#include "allocator/allocator.h"
#include "mdl/mdl.h"
#include "thread/thread.h"

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

BOOL WINAPI DllMain(IN HINSTANCE InstanceHandle, IN DWORD Reason, IN PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH)
        AddVectoredExceptionHandler(1, VEHandler);

    return TRUE;
}
