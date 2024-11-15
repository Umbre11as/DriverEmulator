// ReSharper disable CppParameterNeverUsed
#include <Windows.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdarg.h>

#define EXPORT __declspec(dllexport)

EXPORT ULONG vDbgPrintEx(IN ULONG ComponentId, IN ULONG Level, IN PCSTR Format, IN va_list arglist) {
    char buffer[1024];
    int result = vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, Format, arglist);
    fprintf(Level == 0 ? stdout : stderr, "[vDbgPrintEx]: %s", buffer);

    return result;
}

EXPORT ULONG DbgPrintEx(IN ULONG ComponentId, IN ULONG Level, IN PCSTR Format, ...) {
    va_list args;
    va_start(args, Format);

    ULONG result = vDbgPrintEx(ComponentId, Level, Format, args);

    va_end(args);
    return result;
}

EXPORT ULONG DbgPrint(IN PCSTR Format, ...) {
    va_list args;
    va_start(args, Format);

    ULONG result = vDbgPrintEx(0, 0, Format, args);

    va_end(args);
    return result;
}

typedef ULONG64 POOL_FLAGS;

#define POOL_FLAG_REQUIRED_START          0x0000000000000001UI64
#define POOL_FLAG_USE_QUOTA               0x0000000000000001UI64     // Charge quota
#define POOL_FLAG_UNINITIALIZED           0x0000000000000002UI64     // Don't zero-initialize allocation
#define POOL_FLAG_SESSION                 0x0000000000000004UI64     // Use session specific pool
#define POOL_FLAG_CACHE_ALIGNED           0x0000000000000008UI64     // Cache aligned allocation
#define POOL_FLAG_RESERVED1               0x0000000000000010UI64     // Reserved for system use
#define POOL_FLAG_RAISE_ON_FAILURE        0x0000000000000020UI64     // Raise exception on failure
#define POOL_FLAG_NON_PAGED               0x0000000000000040UI64     // Non paged pool NX
#define POOL_FLAG_NON_PAGED_EXECUTE       0x0000000000000080UI64     // Non paged pool executable
#define POOL_FLAG_PAGED                   0x0000000000000100UI64     // Paged pool
#define POOL_FLAG_RESERVED2               0x0000000000000200UI64     // Reserved for system use
#define POOL_FLAG_RESERVED3               0x0000000000000400UI64     // Reserved for system use
#define POOL_FLAG_REQUIRED_END            0x0000000080000000UI64
#define POOL_FLAG_OPTIONAL_START          0x0000000100000000UI64
#define POOL_FLAG_SPECIAL_POOL            0x0000000100000000UI64     // Make special pool allocation
#define POOL_FLAG_OPTIONAL_END            0x8000000000000000UI64

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32,
} POOL_TYPE;

NTSTATUS ExpPoolFlagsToPoolType(IN POOL_FLAGS Flags, IN INT AlwaysZero, OUT POOL_TYPE* PoolType, OUT BOOLEAN* WithQuotaTag, OUT BOOLEAN* Idk) {
    *Idk = FALSE;

    ULONG64 poolType = NonPagedPool;
    if ((Flags & 0xFFFFF800) != 0 || ((Flags & POOL_FLAG_RESERVED1) != 0 && !AlwaysZero))
        return STATUS_INVALID_PARAMETER;

    switch (Flags & 0x1C0) {
        case POOL_FLAG_NON_PAGED: {
            poolType = NonPagedPoolNx;
            break;
        }
        case POOL_FLAG_PAGED: {
            poolType = STATUS_GUARD_PAGE_VIOLATION;
            if ((Flags & POOL_FLAG_RESERVED1) == 0)
                poolType = PagedPool;

            break;
        }
        default: break;
    }

    int temp = poolType | POOL_FLAG_RAISE_ON_FAILURE;
    if ((Flags & POOL_FLAG_SESSION) == 0)
        temp = poolType;

    poolType = poolType | POOL_FLAG_RESERVED3;
    if ((Flags & POOL_FLAG_UNINITIALIZED) != 0)
        poolType = temp;

    if ((Flags & 0x100000629) != 0) {
        temp = poolType | POOL_FLAG_SESSION;
        if ((Flags & POOL_FLAG_CACHE_ALIGNED) == 0)
            temp = poolType;

        poolType = temp;

        if ((Flags & POOL_FLAG_RESERVED2) != 0)
            poolType |= POOL_FLAG_NON_PAGED_EXECUTE;

        if ((Flags & POOL_FLAG_RESERVED3) != 0)
            poolType |= POOL_FLAG_NON_PAGED;

        if ((Flags & POOL_FLAG_USE_QUOTA) != 0) {
            *WithQuotaTag = TRUE;
            if ((Flags & POOL_FLAG_RAISE_ON_FAILURE) == 0)
                poolType |= POOL_FLAG_CACHE_ALIGNED;
        } else if ((Flags & POOL_FLAG_RAISE_ON_FAILURE) != 0)
            poolType |= POOL_FLAG_RESERVED1;

        if ((Flags & POOL_FLAG_SPECIAL_POOL) != 0)
            *Idk = TRUE;
    }

    *PoolType = poolType;
    return STATUS_SUCCESS;
}

EXPORT PVOID ExAllocatePoolWithTag(IN __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType, IN SIZE_T Size, IN ULONG Tag) {
    PVOID sizedBuffer = VirtualAlloc(NULL, Size + sizeof(Size), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(sizedBuffer, &Size, sizeof(Size));

    return (PVOID) ((UINT_PTR) sizedBuffer + sizeof(Size));
}

EXPORT PVOID ExAllocatePoolWithQuotaTag(IN __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType, IN SIZE_T Size, IN ULONG Tag) {
    return ExAllocatePoolWithTag(PoolType, Size, Tag);
}

EXPORT PVOID ExAllocatePool(IN __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType, IN SIZE_T Size) {
    return ExAllocatePoolWithTag(PoolType, Size, 0x656E6F4E);
}

// Resharper caught schizophrenia :)
// ReSharper disable CppDFAConstantFunctionResult
// ReSharper disable CppDFAUnreachableCode
EXPORT DECLSPEC_RESTRICT PVOID ExAllocatePool2(IN POOL_FLAGS Flags, IN SIZE_T Size, IN ULONG Tag) {
    if (!Tag) {
        fprintf(stderr, "[ExAllocatePool2] Tag not specified\n");
        return NULL;
    }

    BOOLEAN idk;
    BOOLEAN withQuotaTag;
    POOL_TYPE type = NonPagedPool;
    NTSTATUS status = STATUS_SUCCESS;
    if (FAILED(status = ExpPoolFlagsToPoolType(Flags, 0, &type, &withQuotaTag, &idk))) {
        fprintf(stderr, "[ExAllocatePool2] ExpPoolFlagsToPoolType failed: 0x%lX\n", status);
        return NULL;
    }

    if (withQuotaTag)
        return ExAllocatePoolWithQuotaTag(type, Size, Tag);

    return ExAllocatePoolWithTag(type, Size, Tag);
}

typedef PVOID PCPOOL_EXTENDED_PARAMETER;

// TODO: Fully ExAllocatePool3 support
EXPORT DECLSPEC_RESTRICT PVOID ExAllocatePool3(IN POOL_FLAGS Flags, IN SIZE_T Size, IN ULONG Tag, IN PCPOOL_EXTENDED_PARAMETER ExtendedParameters, IN ULONG Count) {
    return ExAllocatePool2(Flags, Size, Tag);
}

// ReSharper restore CppDFAUnreachableCode
// ReSharper restore CppDFAConstantFunctionResult

NTSTATUS ExFreeHeapPool(IN PVOID Buffer) {
    if (Buffer == NULL)
        return STATUS_INVALID_ADDRESS;

    SIZE_T size = 0;
    PVOID sizedBuffer = (PVOID) ((ULONG_PTR) Buffer - sizeof(size));
    memcpy(&size, sizedBuffer, sizeof(size));

    printf("[ExFreeHeapPool] %p with size 0x%lX\n", Buffer, size);
    return VirtualFree(sizedBuffer, size + sizeof(size), MEM_RELEASE) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL; // TODO: Wrap ntstatus with GetLastError
}

EXPORT void ExFreePoolWithTag(IN PVOID Buffer, IN ULONG Tag) {
    // ReSharper disable CppFunctionResultShouldBeUsed
    ExFreeHeapPool(Buffer);
    // ReSharper restore CppFunctionResultShouldBeUsed
}
