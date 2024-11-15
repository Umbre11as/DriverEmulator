#pragma once

#include "../keprocess.h"

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

typedef enum _LOCK_OPERATION {
    IoReadAccess,
    IoWriteAccess,
    IoModifyAccess
} LOCK_OPERATION;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

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

EXPORT PMDL IoAllocateMdl(IN OPTIONAL __drv_aliasesMem PVOID VirtualAddress, IN ULONG Length, IN BOOLEAN SecondaryBuffer, IN BOOLEAN ChargeQuota, IN OUT OPTIONAL PIRP Irp);
EXPORT void IoFreeMdl(IN PMDL Mdl);
EXPORT void MmProbeAndLockPages(IN OUT PMDL Mdl, IN KPROCESSOR_MODE AccessMode, IN LOCK_OPERATION Operation);
EXPORT void MmUnlockPages(IN OUT PMDL Mdl);
EXPORT PVOID MmMapLockedPagesSpecifyCache(IN PMDL Mdl, IN __drv_strictType(KPROCESSOR_MODE / enum _MODE,__drv_typeConst) KPROCESSOR_MODE AccessMode, IN __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType, IN OPTIONAL PVOID RequestedAddress, IN ULONG BugCheckOnFailure /* Microsoft, why it's ULONG? */, IN ULONG Priority);
EXPORT void MmUnmapLockedPages(IN PVOID BaseAddress, IN OUT PMDL Mdl);
EXPORT NTSTATUS MmProtectMdlSystemAddress(IN PMDL Mdl, IN ULONG NewProtect);
