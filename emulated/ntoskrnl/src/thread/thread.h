#pragma once

#include "../ntdll/wrapper.h"

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef void KSTART_ROUTINE(IN PVOID StartContext);
typedef KSTART_ROUTINE *PKSTART_ROUTINE;

EXPORT NTSTATUS KeDelayExecutionThread(IN KPROCESSOR_MODE WaitMode, IN BOOLEAN Alertable, IN PLARGE_INTEGER Interval);
EXPORT NTSTATUS PsCreateSystemThread(OUT PHANDLE ThreadHandle, IN ULONG DesiredAccess, IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes, IN OPTIONAL HANDLE ProcessHandle, OUT OPTIONAL PCLIENT_ID ClientId, IN PKSTART_ROUTINE StartRoutine, IN OPTIONAL PVOID StartContext);
