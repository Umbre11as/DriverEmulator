#include "wrapper.h"

EXPORT NTSTATUS ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID Information, IN ULONG Length, OUT OPTIONAL PULONG ReturnLength) {
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    if (ntdll == NULL)
        ntdll = LoadLibrary("ntdll.dll");

    NtQuerySystemInformationFn nqsi = (NtQuerySystemInformationFn) GetProcAddress(ntdll, "NtQuerySystemInformation");
    return nqsi(SystemInformationClass, Information, Length, ReturnLength);
}

EXPORT NTSTATUS RtlFindExportedRoutineByName(IN PVOID BaseOfImage, IN PCSTR RoutineName) {
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    if (ntdll == NULL)
        ntdll = LoadLibrary("ntdll.dll");

    RtlFindExportedRoutineByNameFn rferbn = (RtlFindExportedRoutineByNameFn) GetProcAddress(ntdll, "RtlFindExportedRoutineByName");
    return rferbn(BaseOfImage, RoutineName);
}
