#pragma once

#include "../types.h"

typedef ULONG64 POOL_FLAGS;

#define DEFAULT_TAG 0x656E6F4E // From IDA

typedef PVOID PCPOOL_EXTENDED_PARAMETER;

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

NTSTATUS ExpPoolFlagsToPoolType(IN POOL_FLAGS Flags, IN INT AlwaysZero, OUT POOL_TYPE* PoolType, OUT BOOLEAN* WithQuotaTag, OUT BOOLEAN* Idk);

EXPORT PVOID ExAllocatePoolWithTag(IN __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType, IN SIZE_T Size, IN ULONG Tag);
EXPORT PVOID ExAllocatePoolWithQuotaTag(IN __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType, IN SIZE_T Size, IN ULONG Tag);
EXPORT PVOID ExAllocatePool(IN __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType, IN SIZE_T Size);
EXPORT DECLSPEC_RESTRICT PVOID ExAllocatePool2(IN POOL_FLAGS Flags, IN SIZE_T Size, IN ULONG Tag);
EXPORT DECLSPEC_RESTRICT PVOID ExAllocatePool3(IN POOL_FLAGS Flags, IN SIZE_T Size, IN ULONG Tag, IN PCPOOL_EXTENDED_PARAMETER ExtendedParameters, IN ULONG Count);
NTSTATUS ExFreeHeapPool(IN PVOID Buffer);
EXPORT void ExFreePoolWithTag(IN PVOID Buffer, IN ULONG Tag);
EXPORT void ExFreePool(IN PVOID Buffer);
EXPORT void ExFreePool2(IN PVOID Buffer, IN ULONG Tag, IN PCPOOL_EXTENDED_PARAMETER ExtendedParameters, IN ULONG Count);
