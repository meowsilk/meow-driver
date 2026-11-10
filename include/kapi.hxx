#pragma once

#include "protocol.hxx"

static const uint64_t kCsKapiMagic = 0x6C91E4A2B7D0583FULL;

enum cs_kapi_id : unsigned {
    cs_kapi_KeWaitForSingleObject = 0,
    cs_kapi_PsCreateSystemThread,
    cs_kapi_PsTerminateSystemThread,
    cs_kapi_IoGetCurrentProcess,
    cs_kapi_ObReferenceObjectByHandle,
    cs_kapi_ObfDereferenceObject,
    cs_kapi_ZwClose,
    cs_kapi_MmGetPhysicalAddress,
    cs_kapi_MmIsAddressValid,
    cs_kapi_MmMapViewInSystemSpace,
    cs_kapi_MmUnmapViewInSystemSpace,
    cs_kapi_PsGetProcessCreateTimeQuadPart,
    cs_kapi_PsGetProcessId,
    cs_kapi_ZwOpenProcess,
    cs_kapi_PsLookupProcessByProcessId,
    cs_kapi_ObOpenObjectByPointer,
    cs_kapi_ZwDuplicateObject,
    cs_kapi_ZwWaitForSingleObject,
    cs_kapi_ExEventObjectType,
    cs_kapi_KeSetEvent,
    cs_kapi_RtlInitUnicodeString,
    cs_kapi_MmGetSystemRoutineAddress,
    cs_kapi_RtlCompareMemory,
    cs_kapi_KeGetCurrentIrql,
    cs_kapi_ExFreePoolWithTag,
    cs_kapi_MmMapLockedPagesSpecifyCache,
    cs_kapi_MmUnmapLockedPages,
    cs_kapi_MmGetPhysicalMemoryRanges,
    cs_kapi_MmGetVirtualForPhysical,
    cs_kapi_PsGetProcessSectionBaseAddress,
    cs_kapi_PsGetProcessPeb,
    cs_kapi_PsThreadType,
    cs_kapi_KeQueryPerformanceCounter,
    cs_kapi_RtlGetVersion,
    cs_kapi_IofCompleteRequest,
    cs_kapi_KeInitializeMutex,
    cs_kapi_KeInitializeEvent,
    cs_kapi_KeClearEvent,
    cs_kapi_ExAllocatePoolWithTag,
    cs_kapi_count
};

struct cs_kapi {
    uint64_t magic;
    volatile uint64_t fn[cs_kapi_count];
};
