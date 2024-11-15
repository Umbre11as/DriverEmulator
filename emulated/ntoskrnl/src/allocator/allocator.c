#include "allocator.h"

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

    ULONG64 temp = poolType | POOL_FLAG_RAISE_ON_FAILURE;
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
    return ExAllocatePoolWithTag(PoolType, Size, DEFAULT_TAG);
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

    printf("[ExFreeHeapPool]: Cleaning %p with size 0x%lX\n", Buffer, size);
    return VirtualFree(sizedBuffer, size + sizeof(size), MEM_RELEASE) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL; // TODO: Wrap ntstatus with GetLastError
}

EXPORT void ExFreePoolWithTag(IN PVOID Buffer, IN ULONG Tag) {
    // ReSharper disable CppFunctionResultShouldBeUsed
    ExFreeHeapPool(Buffer);
    // ReSharper restore CppFunctionResultShouldBeUsed
}

EXPORT void ExFreePool(IN PVOID Buffer) {
    ExFreePoolWithTag(Buffer, DEFAULT_TAG);
}

EXPORT void ExFreePool2(IN PVOID Buffer, IN ULONG Tag, IN PCPOOL_EXTENDED_PARAMETER ExtendedParameters, IN ULONG Count) {
    ExFreePoolWithTag(Buffer, Tag);
}
