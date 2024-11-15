#include "mdl.h"

#include "../allocator/allocator.h"

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

EXPORT void MmProbeAndLockPages(IN OUT PMDL Mdl, IN KPROCESSOR_MODE AccessMode, IN LOCK_OPERATION Operation) {
    DWORD oldProtect = 0;
    VirtualProtect(Mdl->StartVa, Mdl->ByteCount, Operation == IoReadAccess ? PAGE_READONLY : PAGE_EXECUTE_READWRITE, &oldProtect);

    printf("[MmProbeAndLockPages]: AccessMode: 0x%X, Operation: 0x%X\n", AccessMode, Operation);
}

EXPORT void MmUnlockPages(IN OUT PMDL Mdl) {
    DWORD oldProtect = 0;
    VirtualProtect(Mdl->StartVa, Mdl->ByteCount, PAGE_EXECUTE_READWRITE, &oldProtect);
}

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
