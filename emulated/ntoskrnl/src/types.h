#pragma once

#include <Windows.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdarg.h>

#define EXPORT __declspec(dllexport)

typedef CCHAR KPROCESSOR_MODE;
typedef PVOID PIRP;

typedef struct _CSTRING {
    USHORT Length;
    USHORT MaximumLength;
    CONST char *Buffer;
} CSTRING, *PCSTRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;


EXPORT inline NTSTATUS ZwClose(IN HANDLE Handle) {
    return CloseHandle(Handle) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
