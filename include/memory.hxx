#pragma once

#include <ntddk.h>
#include "protocol.hxx"

#ifdef __cplusplus
extern "C" {
#endif

struct cs_pte_view {
    ULONG64 page;
    PVOID view;
};

extern cs_pte_view g_image_pte_views[kCsPteCap];
extern ULONG g_image_pte_view_count;

NTSTATUS CsWalkInit(void);
NTSTATUS CsPrepImagePteViews(void);
void CsWalkReset(void);
void CsWalkDropPid(HANDLE pid);
void CsPhysSelfTest(void);
void CsPhysDiagFill(cs_diag* out);
BOOLEAN CsPhysDiagOk(const cs_diag* d);
NTSTATUS CsReadPhys(ULONG64 pa, PVOID dst, SIZE_T n);
NTSTATUS CsWritePhys(ULONG64 pa, const void* src, SIZE_T n);
NTSTATUS CsWritePhysMdl(ULONG64 pa, const void* src, SIZE_T n);
NTSTATUS CsWritePhysNoWin(ULONG64 pa, const void* src, SIZE_T n);
NTSTATUS CsTranslateVa(ULONG64 va, ULONG64* pa);
NTSTATUS CsPteClearNx(ULONG64 va);
NTSTATUS CsPteClearRw(ULONG64 va);
NTSTATUS CsSplitLarge(ULONG64 va);
NTSTATUS CsOwnPa(PVOID va, ULONG64* pa);
void CsOwnRegister(PVOID va, ULONG64 pa);
NTSTATUS CsPteSetPfn(ULONG64 va, ULONG64 new_pa);
NTSTATUS CsResolveCr3(PEPROCESS process, PVOID image_base, ULONG64 create_time);
NTSTATUS CsCopyOut(PEPROCESS process, ULONG64 va, PVOID dst, SIZE_T bytes);
NTSTATUS CsCopyIn(PEPROCESS process, ULONG64 va, PVOID src, SIZE_T bytes);
PVOID CsProcessBase(PEPROCESS process);

#ifdef __cplusplus
}
#endif
