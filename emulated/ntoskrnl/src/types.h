#pragma once

#include <Windows.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdarg.h>

#define EXPORT __declspec(dllexport)

typedef union _ARM_TTB_REGISTER {
    struct {
        ULONG Reserved:14;
        ULONG BaseAddress:18;
    };
    ULONG AsUlong;
} ARM_TTB_REGISTER;

typedef union _ARM_STATUS_REGISTER {
    struct {
        ULONG Mode:5;
        ULONG State:1;
        ULONG FiqDisable:1;
        ULONG IrqDisable:1;
        ULONG ImpreciseAbort:1;
        ULONG Endianness:1;
        ULONG Sbz:6;
        ULONG GreaterEqual:4;
        ULONG Sbz1:4;
        ULONG Java:1;
        ULONG Sbz2:2;
        ULONG StickyOverflow:1;
        ULONG Overflow:1;
        ULONG CarryBorrowExtend:1;
        ULONG Zero:1;
        ULONG NegativeLessThan:1;
    };
    ULONG AsUlong;
} ARM_STATUS_REGISTER;

typedef UCHAR KIRQL;
typedef KIRQL *PKIRQL;
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
