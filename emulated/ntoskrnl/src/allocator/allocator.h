#pragma once

#include "../keprocess.h"

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
