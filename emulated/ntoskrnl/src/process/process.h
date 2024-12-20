#pragma once

#include "../keprocess.h"

EXPORT PEPROCESS PsInitialSystemProcess;

EXPORT PCSTR PsGetProcessImageFileName(IN PEPROCESS Process);
EXPORT HANDLE PsGetProcessId(IN PEPROCESS Process);
EXPORT HANDLE PsGetCurrentProcessId();
EXPORT NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId, OUT PEPROCESS* Process);
EXPORT PVOID PsGetProcessSectionBaseAddress(IN PEPROCESS Process);
EXPORT HANDLE PsGetCurrentProcessWin32Process();
EXPORT PPEB PsGetProcessPeb(IN PEPROCESS Process);
