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

#define DEFAULT_TAG 0x656E6F4E // From IDA

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

#define MM_DONT_ZERO_ALLOCATION                  0x00000001
#define MM_ALLOCATE_FROM_LOCAL_NODE_ONLY         0x00000002
#define MM_ALLOCATE_FULLY_REQUIRED               0x00000004
#define MM_ALLOCATE_NO_WAIT                      0x00000008
#define MM_ALLOCATE_PREFER_CONTIGUOUS            0x00000010
#define MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS    0x00000020

#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_PAGES_LOCKED            0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE    0x0008
#define MDL_PARTIAL                 0x0010
#define MDL_PARTIAL_HAS_BEEN_MAPPED 0x0020
#define MDL_IO_PAGE_READ            0x0040
#define MDL_WRITE_OPERATION         0x0080
#define MDL_PARENT_MAPPED_SYSTEM_VA 0x0100
#define MDL_FREE_EXTRA_PTES         0x0200
#define MDL_DESCRIBES_AWE           0x0400
#define MDL_IO_SPACE                0x0800
#define MDL_NETWORK_HEADER          0x1000
#define MDL_MAPPING_CAN_FAIL        0x2000
#define MDL_ALLOCATED_MUST_SUCCEED  0x4000
#define MDL_INTERNAL                0x8000

typedef PVOID PEPROCESS;

typedef _Struct_size_bytes_(_Inexpressible_(sizeof(struct _MDL) + (ByteOffset + ByteCount + PAGE_SIZE-1) / PAGE_SIZE * sizeof(PFN_NUMBER))) struct _MDL {
    struct _MDL* Next;
    short Size;
    short MdlFlags;

    PEPROCESS Process;
    PVOID MappedSystemVa;   /* see creators for field size annotations. */
    PVOID StartVa;   /* see creators for validity; could be address 0.  */
    ULONG ByteCount;
    ULONG ByteOffset;
} MDL, *PMDL;

typedef PVOID PIRP;

EXPORT PMDL IoAllocateMdl(IN OPTIONAL __drv_aliasesMem PVOID VirtualAddress, IN ULONG Length, IN BOOLEAN SecondaryBuffer, IN BOOLEAN ChargeQuota, IN OUT OPTIONAL PIRP Irp) {
    PMDL mdl = ExAllocatePool(NonPagedPoolNx, sizeof(MDL));
    SIZE_T size = (((WORD) VirtualAddress & 0xFFF) + (WORD) Length + 4095) >> 12;
    mdl->Next = NULL;
    mdl->Size = 8 * (size + 6);
    mdl->MdlFlags = MDL_ALLOCATED_FIXED_SIZE;
    mdl->ByteCount = Length;
    mdl->Process = (PEPROCESS) 0xFFFFFFFF00000000;
    mdl->MappedSystemVa = VirtualAddress;
    mdl->StartVa = VirtualAddress;
    mdl->ByteOffset = (WORD) VirtualAddress & 0xFFF;
    printf("[IoAllocateMdl]: Allocated mdl: %p\n", mdl);

    return mdl;
}

EXPORT void IoFreeMdl(IN PMDL Mdl) {
    ExFreePool(Mdl);
}

typedef enum _LOCK_OPERATION {
    IoReadAccess,
    IoWriteAccess,
    IoModifyAccess
} LOCK_OPERATION;

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

EXPORT void MmProbeAndLockPages(IN OUT PMDL Mdl, IN KPROCESSOR_MODE AccessMode, IN LOCK_OPERATION Operation) {
    DWORD oldProtect = 0;
    VirtualProtect(Mdl->StartVa, Mdl->ByteCount, Operation == IoReadAccess ? PAGE_READONLY : PAGE_EXECUTE_READWRITE, &oldProtect);

    printf("[MmProbeAndLockPages]: AccessMode: 0x%X, Operation: 0x%X\n", AccessMode, Operation);
}

EXPORT void MmUnlockPages(IN OUT PMDL Mdl) {
    DWORD oldProtect = 0;
    VirtualProtect(Mdl->StartVa, Mdl->ByteCount, PAGE_EXECUTE_READWRITE, &oldProtect);
}

typedef enum _MEMORY_CACHING_TYPE_ORIG {
    MmFrameBufferCached = 2
} MEMORY_CACHING_TYPE_ORIG;

typedef enum _MEMORY_CACHING_TYPE {
    MmNonCached = FALSE,
    MmCached = TRUE,
    MmWriteCombined = MmFrameBufferCached,
    MmHardwareCoherentCached,
    MmNonCachedUnordered,       // IA64
    MmUSWCCached,
    MmMaximumCacheType,
    MmNotMapped = -1
} MEMORY_CACHING_TYPE;

EXPORT PVOID MmMapLockedPagesSpecifyCache(IN PMDL Mdl, IN __drv_strictType(KPROCESSOR_MODE / enum _MODE,__drv_typeConst) KPROCESSOR_MODE AccessMode, IN __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType, IN OPTIONAL PVOID RequestedAddress, IN ULONG BugCheckOnFailure /* Microsoft, why it's ULONG? */, IN ULONG Priority) {
    printf("[MmMapLockedPagesSpecifyCache]: Mapped %p\n", Mdl->MappedSystemVa);
    return Mdl->MappedSystemVa;
}

EXPORT void MmUnmapLockedPages(IN PVOID BaseAddress, IN OUT PMDL Mdl) {
    // Do nothing, lol
}

EXPORT NTSTATUS MmProtectMdlSystemAddress(IN PMDL Mdl, IN ULONG NewProtect) {
    DWORD oldProtect = 0;
    return VirtualProtect(Mdl->MappedSystemVa, Mdl->Size, NewProtect, &oldProtect) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

EXPORT NTSTATUS KeDelayExecutionThread(IN KPROCESSOR_MODE WaitMode, IN BOOLEAN Alertable, IN PLARGE_INTEGER Interval) {
    Sleep(Interval->LowPart); // TODO: Recreate threads
}
