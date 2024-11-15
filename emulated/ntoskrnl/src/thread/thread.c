// ReSharper disable CppParameterNeverUsed
#include "thread.h"

EXPORT NTSTATUS KeDelayExecutionThread(IN KPROCESSOR_MODE WaitMode, IN BOOLEAN Alertable, IN PLARGE_INTEGER Interval) {
    SleepEx(Interval->LowPart, Alertable ? 1 : 0);
    return STATUS_SUCCESS;
}

typedef struct {
    PKSTART_ROUTINE StartRoutine;
    PVOID StartContext;
} RunnerContext;

void KernelThreadRunnerRoutine(IN const RunnerContext* Context) {
    Context->StartRoutine(Context->StartContext);
}

EXPORT NTSTATUS PsCreateSystemThread(OUT PHANDLE ThreadHandle, IN ULONG DesiredAccess, IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes, IN OPTIONAL HANDLE ProcessHandle, OUT OPTIONAL PCLIENT_ID ClientId, IN PKSTART_ROUTINE StartRoutine, IN OPTIONAL PVOID StartContext) {
    RunnerContext context = { StartRoutine, StartContext };

    DWORD id = 0;
    *ThreadHandle = CreateThread(NULL, 0, KernelThreadRunnerRoutine, &context, 0, &id);
    return (*ThreadHandle) != INVALID_HANDLE_VALUE;
}
