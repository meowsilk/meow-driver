#include <ntifs.h>
#include <intrin.h>
#include "memory.hxx"
#include "protocol.hxx"

extern cs_map_slot cs_map_slot_g;

BOOLEAN CsOwnRead(ULONG64 pa, PVOID dst, SIZE_T n);

extern "C" NTSYSAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSYSAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);

#include "kapi_bind.hxx"

cs_pte_view g_image_pte_views[kCsPteCap]{};
ULONG g_image_pte_view_count = 0;

namespace {

constexpr ULONG64 kPresent = 1;
constexpr ULONG64 kLarge = 0x80;
constexpr ULONG64 kPhysMask = 0x000FFFFFFFFFF000ull;
constexpr ULONG64 k1gMask = 0x000FFFFFC0000000ull;
constexpr ULONG64 k2mMask = 0x000FFFFFFFE00000ull;
constexpr ULONG64 kUserVaMax = 0x00007FFFFFFFFFFFull;

struct Cr3Slot {
    HANDLE pid;
    ULONG64 user_dtb;
    ULONG64 kern_dtb;
    ULONG64 create_time;
    PVOID base;
};

Cr3Slot g_cr3;

struct PhysRun {
    ULONG64 start;
    ULONG64 end;
};

PhysRun g_runs[64];
ULONG g_nruns;
constexpr ULONG kMdlPages = kCsOutputBytes / 0x1000;
constexpr SIZE_T kSpanCap = static_cast<SIZE_T>(kMdlPages) * 0x1000;
DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) UCHAR g_mdl_store[sizeof(MDL) + sizeof(PFN_NUMBER) * kMdlPages];
UCHAR g_pt_page[0x1000];
ULONG64 g_pt_pa;
DECLSPEC_ALIGN(4096) UCHAR g_win[4096];
ULONG64 g_win_pte_pa;
ULONG64 g_win_pte;
BOOLEAN g_win_ready;
BOOLEAN g_in_win;
cs_diag g_phys_diag{};
constexpr ULONG64 kNx = 1ull << 63;

NTSTATUS WriteViaWindow(ULONG64 pa, const void* src, SIZE_T n);
NTSTATUS WritePhysMdl(ULONG64 pa, const void* src, SIZE_T n);
NTSTATUS WritePhysNoWin(ULONG64 pa, const void* src, SIZE_T n);
NTSTATUS ReadViaWindow(ULONG64 pa, PVOID dst, SIZE_T n);
NTSTATUS ReadPhysMdl(ULONG64 pa, PVOID dst, SIZE_T n);
NTSTATUS EnsureWin(void);

BOOLEAN PhysOk(ULONG64 pa)
{
    return pa >= 0x1000ull && !(pa & 0xFFFF000000000000ull) && pa < 0x40000000000ull;
}

BOOLEAN PhysRamOk(ULONG64 pa, SIZE_T n)
{
    if (!n || !PhysOk(pa))
        return FALSE;
    const ULONG64 last = pa + (n - 1);
    if (last < pa || !PhysOk(last))
        return FALSE;
    if (!g_nruns)
        return TRUE;
    for (ULONG i = 0; i < g_nruns; ++i) {
        if (pa >= g_runs[i].start && last < g_runs[i].end)
            return TRUE;
    }
    return FALSE;
}

ULONG64 ReadEprocessQword(PEPROCESS process, ULONG off)
{
    if (!process || !off || off >= 0x1000)
        return 0;
    const ULONG64 cand = *reinterpret_cast<ULONG64*>(reinterpret_cast<PUCHAR>(process) + off) & kPhysMask;
    return cand >= 0x1000ull ? cand : 0;
}

PVOID ReadEprocessPtr(PEPROCESS process, ULONG off)
{
    if (!process || !off || off >= 0x1000)
        return nullptr;
    const ULONG64 v = *reinterpret_cast<ULONG64*>(reinterpret_cast<PUCHAR>(process) + off);
    if (v < 0x10000ull || v > kUserVaMax)
        return nullptr;
    return reinterpret_cast<PVOID>(v);
}

NTSTATUS TouchPhys(ULONG64 pa, BOOLEAN write, const void* src, PVOID dst, SIZE_T n)
{
    if (!n || (write && !src) || (!write && !dst))
        return STATUS_INVALID_PARAMETER;
    if (write) {
        if (!PhysRamOk(pa, n))
            return STATUS_INVALID_PARAMETER;
    } else if (!PhysOk(pa)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    const ULONG64 page = pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    if (off + n > 0x1000)
        return STATUS_INVALID_PARAMETER;

    if (!write) {
        if (CsOwnRead(pa, dst, n))
            return STATUS_SUCCESS;
        PHYSICAL_ADDRESS spa{};
        spa.QuadPart = static_cast<LONGLONG>(page);
        PVOID direct = MmGetVirtualForPhysical(spa);
        if (direct && MmIsAddressValid(static_cast<PUCHAR>(direct) + off + (n - 1))) {
            RtlCopyMemory(dst, static_cast<PUCHAR>(direct) + off, n);
            return STATUS_SUCCESS;
        }
        NTSTATUS st = ReadPhysMdl(pa, dst, n);
        if (NT_SUCCESS(st))
            return st;
        if (g_in_win)
            return st;
        return ReadViaWindow(pa, dst, n);
    }

    PHYSICAL_ADDRESS spa{};
    spa.QuadPart = static_cast<LONGLONG>(page);
    PVOID direct = MmGetVirtualForPhysical(spa);
    if (direct && MmIsAddressValid(static_cast<PUCHAR>(direct) + off + (n - 1))) {
        RtlCopyMemory(static_cast<PUCHAR>(direct) + off, src, n);
        return STATUS_SUCCESS;
    }
    const NTSTATUS mdl = WritePhysMdl(pa, src, n);
    if (NT_SUCCESS(mdl))
        return mdl;
    return WriteViaWindow(pa, src, n);
}

NTSTATUS WritePhysNoWin(ULONG64 pa, const void* src, SIZE_T n)
{
    if (!src || !n || !PhysRamOk(pa, n))
        return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    const ULONG64 page = pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    if (off + n > 0x1000)
        return STATUS_INVALID_PARAMETER;
    PHYSICAL_ADDRESS spa{};
    spa.QuadPart = static_cast<LONGLONG>(page);
    PVOID direct = MmGetVirtualForPhysical(spa);
    if (direct && MmIsAddressValid(static_cast<PUCHAR>(direct) + off + (n - 1))) {
        RtlCopyMemory(static_cast<PUCHAR>(direct) + off, src, n);
        return STATUS_SUCCESS;
    }
    return WritePhysMdl(pa, src, n);
}

NTSTATUS WritePhysMdl(ULONG64 pa, const void* src, SIZE_T n)
{
    const ULONG64 page = pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    UCHAR stack_local = 0;
    const PHYSICAL_ADDRESS stk = MmGetPhysicalAddress(&stack_local);
    if (stk.QuadPart && (static_cast<ULONG64>(stk.QuadPart) & ~0xFFFull) == page)
        return STATUS_ACCESS_DENIED;
    const PHYSICAL_ADDRESS self = MmGetPhysicalAddress(reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(&WritePhysMdl) & ~0xFFFull));
    if (self.QuadPart && (static_cast<ULONG64>(self.QuadPart) & ~0xFFFull) == page)
        return STATUS_ACCESS_DENIED;
    const PHYSICAL_ADDRESS store = MmGetPhysicalAddress(g_mdl_store);
    if (store.QuadPart && (static_cast<ULONG64>(store.QuadPart) & ~0xFFFull) == page)
        return STATUS_ACCESS_DENIED;
    const ULONG64 base = cs_map_slot_g.image_base;
    const ULONG64 size = cs_map_slot_g.image_size;
    if (base >= 0xFFFF800000000000ull && size >= 0x1000ull && size <= 0x100000ull) {
        const ULONG64 first = base & ~0xFFFull;
        const ULONG64 span = (size + 0xFFFull) & ~0xFFFull;
        if (span >= size && first + span > first) {
            for (ULONG64 va = first; va < first + span; va += 0x1000) {
                const PHYSICAL_ADDRESS a = MmGetPhysicalAddress(reinterpret_cast<PVOID>(va));
                if (a.QuadPart && (static_cast<ULONG64>(a.QuadPart) & ~0xFFFull) == page)
                    return STATUS_ACCESS_DENIED;
            }
        }
    }
    auto* mdl = reinterpret_cast<PMDL>(g_mdl_store);
    RtlZeroMemory(g_mdl_store, sizeof(g_mdl_store));
    MmInitializeMdl(mdl, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(page)), PAGE_SIZE);
    mdl->MdlFlags |= static_cast<USHORT>(MDL_PAGES_LOCKED | MDL_ALLOCATED_FIXED_SIZE);
    *MmGetMdlPfnArray(mdl) = static_cast<PFN_NUMBER>(page >> 12);
    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        nullptr,
        FALSE,
        NormalPagePriority);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(static_cast<PUCHAR>(mapped) + off, src, n);
    MmUnmapLockedPages(mapped, mdl);
    return STATUS_SUCCESS;
}

NTSTATUS ReadPhysMdl(ULONG64 pa, PVOID dst, SIZE_T n)
{
    const ULONG64 page = pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    auto* mdl = reinterpret_cast<PMDL>(g_mdl_store);
    RtlZeroMemory(g_mdl_store, sizeof(g_mdl_store));
    MmInitializeMdl(mdl, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(page)), PAGE_SIZE);
    mdl->MdlFlags |= static_cast<USHORT>(MDL_PAGES_LOCKED | MDL_ALLOCATED_FIXED_SIZE);
    *MmGetMdlPfnArray(mdl) = static_cast<PFN_NUMBER>(page >> 12);
    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        nullptr,
        FALSE,
        NormalPagePriority);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(dst, static_cast<PUCHAR>(mapped) + off, n);
    MmUnmapLockedPages(mapped, mdl);
    return STATUS_SUCCESS;
}

NTSTATUS ReadPhys(ULONG64 pa, PVOID dst, SIZE_T n)
{
    return TouchPhys(pa, FALSE, nullptr, dst, n);
}

NTSTATUS WritePhys(ULONG64 pa, const void* src, SIZE_T n)
{
    return TouchPhys(pa, TRUE, src, nullptr, n);
}

NTSTATUS TranslateLeaf(ULONG64 cr3, ULONG64 va, ULONG64* pa)
{
    if (!pa || !cr3)
        return STATUS_INVALID_PARAMETER;
    *pa = 0;
    const ULONG64 pml4 = cr3 & kPhysMask;
    ULONG64 e4 = 0;
    NTSTATUS st = ReadPhys(pml4 + ((va >> 39) & 0x1FF) * 8, &e4, 8);
    if (!NT_SUCCESS(st))
        return st;
    if (!(e4 & kPresent))
        return STATUS_NOT_FOUND;
    ULONG64 e3 = 0;
    st = ReadPhys((e4 & kPhysMask) + ((va >> 30) & 0x1FF) * 8, &e3, 8);
    if (!NT_SUCCESS(st))
        return st;
    if (!(e3 & kPresent))
        return STATUS_NOT_FOUND;
    if (e3 & kLarge) {
        const ULONG64 out = (e3 & k1gMask) | (va & 0x3FFFFFFFull);
        if (out < 0x1000ull)
            return STATUS_NOT_FOUND;
        *pa = out;
        return STATUS_SUCCESS;
    }
    ULONG64 e2 = 0;
    st = ReadPhys((e3 & kPhysMask) + ((va >> 21) & 0x1FF) * 8, &e2, 8);
    if (!NT_SUCCESS(st))
        return st;
    if (!(e2 & kPresent))
        return STATUS_NOT_FOUND;
    if (e2 & kLarge) {
        const ULONG64 out = (e2 & k2mMask) | (va & 0x1FFFFFull);
        if (out < 0x1000ull)
            return STATUS_NOT_FOUND;
        *pa = out;
        return STATUS_SUCCESS;
    }
    ULONG64 e1 = 0;
    st = ReadPhys((e2 & kPhysMask) + ((va >> 12) & 0x1FF) * 8, &e1, 8);
    if (!NT_SUCCESS(st))
        return st;
    if (!(e1 & kPresent))
        return STATUS_NOT_FOUND;
    const ULONG64 out = (e1 & kPhysMask) | (va & 0xFFFull);
    if (out < 0x1000ull)
        return STATUS_NOT_FOUND;
    *pa = out;
    return STATUS_SUCCESS;
}

NTSTATUS TranslatePte(ULONG64 cr3, ULONG64 va, ULONG64* pa, ULONG64* pte_pa, ULONG64* pte_val)
{
    if (!pa || !pte_pa || !pte_val || !cr3)
        return STATUS_INVALID_PARAMETER;
    *pa = 0;
    *pte_pa = 0;
    *pte_val = 0;
    const ULONG64 pml4 = cr3 & kPhysMask;
    ULONG64 e4 = 0;
    NTSTATUS st = ReadPhys(pml4 + ((va >> 39) & 0x1FF) * 8, &e4, 8);
    if (!NT_SUCCESS(st))
        return st;
    if (!(e4 & kPresent))
        return STATUS_NOT_FOUND;
    ULONG64 e3 = 0;
    st = ReadPhys((e4 & kPhysMask) + ((va >> 30) & 0x1FF) * 8, &e3, 8);
    if (!NT_SUCCESS(st))
        return st;
    if (!(e3 & kPresent))
        return STATUS_NOT_FOUND;
    if (e3 & kLarge) {
        const ULONG64 out = (e3 & k1gMask) | (va & 0x3FFFFFFFull);
        if (out < 0x1000ull)
            return STATUS_NOT_FOUND;
        *pa = out;
        *pte_pa = (e4 & kPhysMask) + ((va >> 30) & 0x1FF) * 8;
        *pte_val = e3;
        return STATUS_SUCCESS;
    }
    ULONG64 e2 = 0;
    st = ReadPhys((e3 & kPhysMask) + ((va >> 21) & 0x1FF) * 8, &e2, 8);
    if (!NT_SUCCESS(st))
        return st;
    if (!(e2 & kPresent))
        return STATUS_NOT_FOUND;
    if (e2 & kLarge) {
        const ULONG64 out = (e2 & k2mMask) | (va & 0x1FFFFFull);
        if (out < 0x1000ull)
            return STATUS_NOT_FOUND;
        *pa = out;
        *pte_pa = (e3 & kPhysMask) + ((va >> 21) & 0x1FF) * 8;
        *pte_val = e2;
        return STATUS_SUCCESS;
    }
    const ULONG64 slot = (e2 & kPhysMask) + ((va >> 12) & 0x1FF) * 8;
    ULONG64 e1 = 0;
    st = ReadPhys(slot, &e1, 8);
    if (!NT_SUCCESS(st))
        return st;
    if (!(e1 & kPresent))
        return STATUS_NOT_FOUND;
    const ULONG64 out = (e1 & kPhysMask) | (va & 0xFFFull);
    if (out < 0x1000ull)
        return STATUS_NOT_FOUND;
    *pa = out;
    *pte_pa = slot;
    *pte_val = e1;
    return STATUS_SUCCESS;
}

NTSTATUS WritePteVal(ULONG64 pte_pa, ULONG64 val)
{
    const ULONG64 page = pte_pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pte_pa & 0xFFF);
    PHYSICAL_ADDRESS spa{};
    spa.QuadPart = static_cast<LONGLONG>(page);
    PVOID direct = MmGetVirtualForPhysical(spa);
    if (direct && MmIsAddressValid(static_cast<PUCHAR>(direct) + off + 7)) {
        *reinterpret_cast<ULONG64*>(static_cast<PUCHAR>(direct) + off) = val;
        return STATUS_SUCCESS;
    }
    return WritePhysMdl(pte_pa, &val, sizeof(val));
}

NTSTATUS EnsureWin(void)
{
    if (g_win_ready)
        return STATUS_SUCCESS;
    ULONG64 win_pa = 0;
    ULONG64 pte_pa = 0;
    ULONG64 pte = 0;
    const NTSTATUS st = TranslatePte(__readcr3() & kPhysMask, reinterpret_cast<ULONG64>(g_win), &win_pa, &pte_pa, &pte);
    if (!NT_SUCCESS(st))
        return st;
    if (pte & kLarge)
        return STATUS_NOT_SUPPORTED;
    g_win_pte_pa = pte_pa;
    g_win_pte = pte;
    g_win_ready = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS WriteViaWindow(ULONG64 pa, const void* src, SIZE_T n)
{
    if (!src || !n || n > PAGE_SIZE)
        return STATUS_INVALID_PARAMETER;
    const ULONG64 page = pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    if (off + n > PAGE_SIZE)
        return STATUS_INVALID_PARAMETER;
    g_in_win = TRUE;
    NTSTATUS st = EnsureWin();
    if (!NT_SUCCESS(st)) {
        g_in_win = FALSE;
        return st;
    }
    const ULONG64 npte = (g_win_pte & ~kPhysMask) | (page & kPhysMask) | kPresent;
    st = WritePteVal(g_win_pte_pa, npte);
    if (!NT_SUCCESS(st)) {
        g_in_win = FALSE;
        return st;
    }
    __invlpg(g_win);
    RtlCopyMemory(g_win + off, src, n);
    st = WritePteVal(g_win_pte_pa, g_win_pte);
    __invlpg(g_win);
    g_in_win = FALSE;
    return st;
}

NTSTATUS ReadViaWindow(ULONG64 pa, PVOID dst, SIZE_T n)
{
    if (!dst || !n || n > PAGE_SIZE)
        return STATUS_INVALID_PARAMETER;
    const ULONG64 page = pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    if (off + n > PAGE_SIZE)
        return STATUS_INVALID_PARAMETER;
    g_in_win = TRUE;
    NTSTATUS st = EnsureWin();
    if (!NT_SUCCESS(st)) {
        g_in_win = FALSE;
        return st;
    }
    const ULONG64 npte = (g_win_pte & ~kPhysMask) | (page & kPhysMask) | kPresent;
    st = WritePteVal(g_win_pte_pa, npte);
    if (!NT_SUCCESS(st)) {
        g_in_win = FALSE;
        return st;
    }
    __invlpg(g_win);
    RtlCopyMemory(dst, g_win + off, n);
    st = WritePteVal(g_win_pte_pa, g_win_pte);
    __invlpg(g_win);
    g_in_win = FALSE;
    return st;
}

NTSTATUS ProbeCr3Mz(ULONG64 dtb, PVOID image_base, BOOLEAN* hit)
{
    if (hit)
        *hit = FALSE;
    if (!dtb || !image_base || !hit)
        return STATUS_INVALID_PARAMETER;
    ULONG64 pa = 0;
    const NTSTATUS st = TranslateLeaf(dtb, reinterpret_cast<ULONG64>(image_base), &pa);
    if (!NT_SUCCESS(st))
        return st;
    USHORT mz = 0;
    const NTSTATUS rst = ReadPhys(pa, &mz, sizeof(mz));
    if (!NT_SUCCESS(rst))
        return rst;
    *hit = mz == 0x5A4D;
    return STATUS_SUCCESS;
}

BOOLEAN Cr3MapsMz(ULONG64 dtb, PVOID image_base)
{
    BOOLEAN hit = FALSE;
    return NT_SUCCESS(ProbeCr3Mz(dtb, image_base, &hit)) && hit;
}

ULONG64 DtbForVa(ULONG64 va)
{
    if (va <= kUserVaMax)
        return g_cr3.user_dtb ? g_cr3.user_dtb : g_cr3.kern_dtb;
    return g_cr3.kern_dtb ? g_cr3.kern_dtb : g_cr3.user_dtb;
}

struct PtCache {
    ULONG64 dtb;
    ULONG pml4_i;
    ULONG64 e4;
    ULONG pdpt_i;
    ULONG64 e3;
    ULONG pd_i;
    ULONG64 e2;
    UCHAR level;
};

NTSTATUS LoadPt(ULONG64 pt)
{
    if (!pt)
        return STATUS_NOT_FOUND;
    if (g_pt_pa == pt)
        return STATUS_SUCCESS;
    const NTSTATUS st = ReadPhys(pt, g_pt_page, 0x1000);
    if (!NT_SUCCESS(st)) {
        g_pt_pa = 0;
        return st;
    }
    g_pt_pa = pt;
    return STATUS_SUCCESS;
}

NTSTATUS CachedLeaf(PtCache* c, ULONG64 va, ULONG64* pa, SIZE_T* leaf_left)
{
    if (!c || !pa || !leaf_left)
        return STATUS_INVALID_PARAMETER;
    *pa = 0;
    *leaf_left = 0;
    const ULONG64 dtb = DtbForVa(va);
    if (!dtb)
        return STATUS_NOT_FOUND;
    if (c->dtb != dtb) {
        c->dtb = dtb;
        c->level = 0;
        g_pt_pa = 0;
    }
    const ULONG i4 = static_cast<ULONG>((va >> 39) & 0x1FF);
    if (c->level < 1 || c->pml4_i != i4) {
        const NTSTATUS st = ReadPhys((dtb & kPhysMask) + static_cast<ULONG64>(i4) * 8, &c->e4, 8);
        if (!NT_SUCCESS(st))
            return st;
        c->pml4_i = i4;
        c->level = 1;
        g_pt_pa = 0;
    }
    if (!(c->e4 & kPresent))
        return STATUS_NOT_FOUND;
    const ULONG i3 = static_cast<ULONG>((va >> 30) & 0x1FF);
    if (c->level < 2 || c->pdpt_i != i3) {
        const NTSTATUS st = ReadPhys((c->e4 & kPhysMask) + static_cast<ULONG64>(i3) * 8, &c->e3, 8);
        if (!NT_SUCCESS(st))
            return st;
        c->pdpt_i = i3;
        c->level = 2;
        g_pt_pa = 0;
    }
    if (!(c->e3 & kPresent))
        return STATUS_NOT_FOUND;
    if (c->e3 & kLarge) {
        const ULONG64 out = (c->e3 & k1gMask) | (va & 0x3FFFFFFFull);
        if (out < 0x1000ull)
            return STATUS_NOT_FOUND;
        *pa = out;
        *leaf_left = static_cast<SIZE_T>(0x40000000ull - (va & 0x3FFFFFFFull));
        return STATUS_SUCCESS;
    }
    const ULONG i2 = static_cast<ULONG>((va >> 21) & 0x1FF);
    if (c->level < 3 || c->pd_i != i2) {
        const NTSTATUS st = ReadPhys((c->e3 & kPhysMask) + static_cast<ULONG64>(i2) * 8, &c->e2, 8);
        if (!NT_SUCCESS(st))
            return st;
        c->pd_i = i2;
        c->level = 3;
        g_pt_pa = 0;
    }
    if (!(c->e2 & kPresent))
        return STATUS_NOT_FOUND;
    if (c->e2 & kLarge) {
        const ULONG64 out = (c->e2 & k2mMask) | (va & 0x1FFFFFull);
        if (out < 0x1000ull)
            return STATUS_NOT_FOUND;
        *pa = out;
        *leaf_left = static_cast<SIZE_T>(0x200000ull - (va & 0x1FFFFFull));
        return STATUS_SUCCESS;
    }
    const ULONG64 pt = c->e2 & kPhysMask;
    const NTSTATUS st = LoadPt(pt);
    if (!NT_SUCCESS(st))
        return st;
    const ULONG i1 = static_cast<ULONG>((va >> 12) & 0x1FF);
    ULONG64 e1 = 0;
    RtlCopyMemory(&e1, g_pt_page + static_cast<SIZE_T>(i1) * 8, sizeof(e1));
    if (!(e1 & kPresent))
        return STATUS_NOT_FOUND;
    const ULONG64 out = (e1 & kPhysMask) | (va & 0xFFFull);
    if (out < 0x1000ull)
        return STATUS_NOT_FOUND;
    *pa = out;
    *leaf_left = static_cast<SIZE_T>(0x1000ull - (va & 0xFFFull));
    return STATUS_SUCCESS;
}

NTSTATUS WriteSpanMdl(ULONG64 pa, const void* src, SIZE_T n)
{
    const ULONG64 first = pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pa - first);
    const ULONG pages = static_cast<ULONG>((off + n + 0xFFF) >> 12);
    if (!pages || pages > kMdlPages)
        return STATUS_INVALID_PARAMETER;
    auto* mdl = reinterpret_cast<PMDL>(g_mdl_store);
    RtlZeroMemory(g_mdl_store, sizeof(g_mdl_store));
    MmInitializeMdl(mdl, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(first)), pages * static_cast<ULONG>(PAGE_SIZE));
    mdl->MdlFlags |= static_cast<USHORT>(MDL_PAGES_LOCKED | MDL_ALLOCATED_FIXED_SIZE);
    PFN_NUMBER* pfns = MmGetMdlPfnArray(mdl);
    for (ULONG i = 0; i < pages; ++i)
        pfns[i] = static_cast<PFN_NUMBER>((first >> 12) + i);
    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        nullptr,
        FALSE,
        NormalPagePriority);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(static_cast<PUCHAR>(mapped) + off, src, n);
    MmUnmapLockedPages(mapped, mdl);
    return STATUS_SUCCESS;
}

NTSTATUS WriteSpan(ULONG64 pa, const void* src, SIZE_T n)
{
    if (!src || !n)
        return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (PhysRamOk(pa, n)) {
        const ULONG64 page = pa & ~0xFFFull;
        const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
        const ULONG64 last_page = (pa + (n - 1)) & ~0xFFFull;
        PHYSICAL_ADDRESS spa{};
        spa.QuadPart = static_cast<LONGLONG>(page);
        PHYSICAL_ADDRESS last{};
        last.QuadPart = static_cast<LONGLONG>(last_page);
        PVOID direct = MmGetVirtualForPhysical(spa);
        PVOID direct_last = MmGetVirtualForPhysical(last);
        const ULONG64 delta = last_page - page;
        if (direct && direct_last
            && direct_last == static_cast<PUCHAR>(direct) + delta
            && MmIsAddressValid(static_cast<PUCHAR>(direct) + off)
            && MmIsAddressValid(static_cast<PUCHAR>(direct) + off + (n - 1))) {
            RtlCopyMemory(static_cast<PUCHAR>(direct) + off, src, n);
            return STATUS_SUCCESS;
        }
        const NTSTATUS mdl = WriteSpanMdl(pa, src, n);
        if (NT_SUCCESS(mdl))
            return mdl;
    }
    auto* p = static_cast<const UCHAR*>(src);
    while (n) {
        const SIZE_T page_off = static_cast<SIZE_T>(pa & 0xFFF);
        SIZE_T chunk = 0x1000 - page_off;
        if (chunk > n)
            chunk = n;
        const NTSTATUS st = WritePhys(pa, p, chunk);
        if (!NT_SUCCESS(st))
            return st;
        p += chunk;
        pa += chunk;
        n -= chunk;
    }
    return STATUS_SUCCESS;
}

NTSTATUS ReadSpan(ULONG64 pa, PVOID dst, SIZE_T n)
{
    if (!dst || !n)
        return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    if (n <= 0x1000 && off + n <= 0x1000 && CsOwnRead(pa, dst, n))
        return STATUS_SUCCESS;
    if (PhysRamOk(pa, n)) {
        const ULONG64 page = pa & ~0xFFFull;
        const ULONG64 last_page = (pa + (n - 1)) & ~0xFFFull;
        PHYSICAL_ADDRESS spa{};
        spa.QuadPart = static_cast<LONGLONG>(page);
        PHYSICAL_ADDRESS last{};
        last.QuadPart = static_cast<LONGLONG>(last_page);
        PVOID direct = MmGetVirtualForPhysical(spa);
        PVOID direct_last = MmGetVirtualForPhysical(last);
        const ULONG64 delta = last_page - page;
        if (direct && direct_last
            && direct_last == static_cast<PUCHAR>(direct) + delta
            && MmIsAddressValid(static_cast<PUCHAR>(direct) + off)
            && MmIsAddressValid(static_cast<PUCHAR>(direct) + off + (n - 1))) {
            RtlCopyMemory(dst, static_cast<PUCHAR>(direct) + off, n);
            return STATUS_SUCCESS;
        }
    }
    auto* p = static_cast<PUCHAR>(dst);
    while (n) {
        const SIZE_T page_off = static_cast<SIZE_T>(pa & 0xFFF);
        SIZE_T chunk = 0x1000 - page_off;
        if (chunk > n)
            chunk = n;
        const NTSTATUS one = ReadPhys(pa, p, chunk);
        if (!NT_SUCCESS(one))
            return one;
        p += chunk;
        pa += chunk;
        n -= chunk;
    }
    return STATUS_SUCCESS;
}

NTSTATUS CopyRange(BOOLEAN to_process, ULONG64 va, PVOID buf, SIZE_T bytes)
{
    if (!buf || !bytes || !va)
        return STATUS_INVALID_PARAMETER;
    PtCache cache{};
    g_pt_pa = 0;
    auto* p = static_cast<PUCHAR>(buf);
    while (bytes) {
        ULONG64 pa = 0;
        SIZE_T leaf_left = 0;
        NTSTATUS st = CachedLeaf(&cache, va, &pa, &leaf_left);
        if (!NT_SUCCESS(st))
            return st;
        if (!leaf_left)
            return STATUS_NOT_FOUND;
        SIZE_T chunk = leaf_left;
        if (chunk > bytes)
            chunk = bytes;
        if (chunk > kSpanCap)
            chunk = kSpanCap;
        while (chunk < bytes && chunk < kSpanCap) {
            ULONG64 npa = 0;
            SIZE_T nleft = 0;
            const NTSTATUS ns = CachedLeaf(&cache, va + chunk, &npa, &nleft);
            if (!NT_SUCCESS(ns) || !nleft || npa != pa + chunk)
                break;
            SIZE_T add = nleft;
            if (add > bytes - chunk)
                add = bytes - chunk;
            if (chunk + add > kSpanCap)
                add = kSpanCap - chunk;
            if (!add)
                break;
            chunk += add;
        }
        if (to_process)
            st = WriteSpan(pa, p, chunk);
        else
            st = ReadSpan(pa, p, chunk);
        if (!NT_SUCCESS(st))
            return st;
        p += chunk;
        va += chunk;
        bytes -= chunk;
    }
    return STATUS_SUCCESS;
}

PVOID BaseFromPeb(PEPROCESS process)
{
    if (!process)
        return nullptr;
    const ULONG64 user = ReadEprocessQword(process, cs_map_slot_g.user_dtb_off);
    const ULONG64 kern = ReadEprocessQword(process, cs_map_slot_g.kern_dtb_off);
    const ULONG64 dtb = user ? user : kern;
    PVOID peb = PsGetProcessPeb(process);
    if (!peb)
        peb = ReadEprocessPtr(process, cs_map_slot_g.peb_off);
    const ULONG img_off = cs_map_slot_g.peb_image_off;
    if (!peb || !dtb || !img_off || img_off >= 0x1000)
        return nullptr;
    const ULONG64 va = reinterpret_cast<ULONG64>(peb) + img_off;
    ULONG64 pa = 0;
    NTSTATUS st = TranslateLeaf(dtb, va, &pa);
    if (!NT_SUCCESS(st) && kern && kern != dtb)
        st = TranslateLeaf(kern, va, &pa);
    if (!NT_SUCCESS(st) || !pa)
        return nullptr;
    ULONG64 image = 0;
    if (!NT_SUCCESS(ReadPhys(pa, &image, sizeof(image))))
        return nullptr;
    if (image < 0x10000ull || image > kUserVaMax)
        return nullptr;
    return reinterpret_cast<PVOID>(image);
}

void CacheCr3(HANDLE pid, ULONG64 create_time, PVOID image_base, ULONG64 pick, ULONG64 kern)
{
    RtlZeroMemory(&g_cr3, sizeof(g_cr3));
    g_cr3.pid = pid;
    g_cr3.create_time = create_time;
    g_cr3.base = image_base;
    g_cr3.user_dtb = pick;
    g_cr3.kern_dtb = kern ? kern : pick;
}

}

static void ReleaseImagePteViews(void)
{
    for (ULONG i = 0; i < g_image_pte_view_count; ++i) {
        g_image_pte_views[i].page = 0;
        g_image_pte_views[i].view = nullptr;
    }
    g_image_pte_view_count = 0;
}

static BOOLEAN PteSlotValid(PVOID view, SIZE_T off)
{
    if (!view || off > 0xFF8)
        return FALSE;
    auto* slot = static_cast<PUCHAR>(view) + off;
    return MmIsAddressValid(slot) && MmIsAddressValid(slot + 7);
}

static BOOLEAN AcquireImagePteView(ULONG64 pte_pa, cs_pte_view* out)
{
    if (!out || !pte_pa || (pte_pa & 7))
        return FALSE;
    const ULONG64 page = pte_pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pte_pa & 0xFFF);
    PHYSICAL_ADDRESS spa{};
    spa.QuadPart = static_cast<LONGLONG>(page);
    PVOID virt = MmGetVirtualForPhysical(spa);
    if (!PteSlotValid(virt, off))
        return FALSE;
    out->page = page;
    out->view = virt;
    return TRUE;
}

NTSTATUS CsPrepImagePteViews(void)
{
    ReleaseImagePteViews();
    const uint32_t n = cs_map_slot_g.pte_count;
    if (!n || n > kCsPteCap)
        return STATUS_INVALID_PARAMETER;
    for (uint32_t i = 0; i < n; ++i) {
        const ULONG64 pte_pa = cs_map_slot_g.pte[i].pte_pa;
        if (!pte_pa || (pte_pa & 7)) {
            ReleaseImagePteViews();
            return STATUS_INVALID_PARAMETER;
        }
        const ULONG64 page = pte_pa & ~0xFFFull;
        const SIZE_T off = static_cast<SIZE_T>(pte_pa & 0xFFF);
        BOOLEAN seen = FALSE;
        for (ULONG j = 0; j < g_image_pte_view_count; ++j) {
            if (g_image_pte_views[j].page != page)
                continue;
            seen = TRUE;
            if (!PteSlotValid(g_image_pte_views[j].view, off)) {
                ReleaseImagePteViews();
                return STATUS_UNSUCCESSFUL;
            }
            break;
        }
        if (seen)
            continue;
        if (g_image_pte_view_count >= kCsPteCap) {
            ReleaseImagePteViews();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (!AcquireImagePteView(pte_pa, &g_image_pte_views[g_image_pte_view_count])) {
            ReleaseImagePteViews();
            return STATUS_UNSUCCESSFUL;
        }
        g_image_pte_view_count += 1;
    }
    return STATUS_SUCCESS;
}

void CsWalkReset(void)
{
    RtlZeroMemory(&g_cr3, sizeof(g_cr3));
    g_pt_pa = 0;
}

void CsWalkDropPid(HANDLE pid)
{
    if (pid && g_cr3.pid == pid)
        RtlZeroMemory(&g_cr3, sizeof(g_cr3));
}

PVOID CsProcessBase(PEPROCESS process)
{
    if (!process)
        return nullptr;
    PVOID image = PsGetProcessSectionBaseAddress(process);
    if (image)
        return image;
    image = ReadEprocessPtr(process, cs_map_slot_g.section_base_off);
    if (image)
        return image;
    return BaseFromPeb(process);
}

NTSTATUS CsWalkInit(void)
{
    if (g_nruns)
        return STATUS_SUCCESS;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    PPHYSICAL_MEMORY_RANGE r = MmGetPhysicalMemoryRanges();
    if (!r)
        return STATUS_INSUFFICIENT_RESOURCES;
    ULONG n = 0;
    for (; n < 64; ++n) {
        const ULONG64 start = static_cast<ULONG64>(r[n].BaseAddress.QuadPart);
        const ULONG64 bytes = static_cast<ULONG64>(r[n].NumberOfBytes.QuadPart);
        if (!start && !bytes)
            break;
        g_runs[n].start = start;
        ULONG64 end = start + bytes;
        if (end < start)
            end = ~0ull;
        g_runs[n].end = end;
    }
    ExFreePool(r);
    g_nruns = n;
    return n ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

BOOLEAN CsPhysDiagOk(const cs_diag* d)
{
    if (!d || d->status)
        return FALSE;
    return RtlCompareMemory(d->what, "physok", 6) == 6
        || RtlCompareMemory(d->what, "selfmz", 6) == 6;
}

void KeepPhysDiag(void)
{
    if (CsPhysDiagOk(&cs_map_slot_g.diag))
        g_phys_diag = cs_map_slot_g.diag;
}

void CsPhysSelfTest(void)
{
    RtlZeroMemory(&cs_map_slot_g.diag, sizeof(cs_map_slot_g.diag));
    cs_map_slot_g.diag.stage = cs_stage_init;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        cs_map_slot_g.diag.status = static_cast<int32_t>(STATUS_INVALID_DEVICE_STATE);
        RtlCopyMemory(cs_map_slot_g.diag.what, "physfail", sizeof("physfail"));
        KeepPhysDiag();
        return;
    }
    const ULONG64 cr3 = __readcr3() & kPhysMask;
    if (!cr3) {
        cs_map_slot_g.diag.status = static_cast<int32_t>(STATUS_NOT_FOUND);
        RtlCopyMemory(cs_map_slot_g.diag.what, "physfail", sizeof("physfail"));
        KeepPhysDiag();
        return;
    }
    ULONG64 pml4e = 0;
    NTSTATUS st = ReadPhys(cr3, &pml4e, sizeof(pml4e));
    if (!NT_SUCCESS(st)) {
        cs_map_slot_g.diag.status = static_cast<int32_t>(NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st);
        RtlCopyMemory(cs_map_slot_g.diag.what, "physfail", sizeof("physfail"));
        KeepPhysDiag();
        return;
    }
    BOOLEAN hit = FALSE;
    st = ProbeCr3Mz(cr3, reinterpret_cast<PVOID>(cs_map_slot_g.image_base), &hit);
    cs_map_slot_g.diag.status = 0;
    if (NT_SUCCESS(st) && hit)
        RtlCopyMemory(cs_map_slot_g.diag.what, "selfmz", sizeof("selfmz"));
    else
        RtlCopyMemory(cs_map_slot_g.diag.what, "physok", sizeof("physok"));
    KeepPhysDiag();
}

void CsPhysDiagFill(cs_diag* out)
{
    if (out)
        *out = g_phys_diag;
}

NTSTATUS CsReadPhys(ULONG64 pa, PVOID dst, SIZE_T n)
{
    return ReadPhys(pa, dst, n);
}

NTSTATUS CsWritePhys(ULONG64 pa, const void* src, SIZE_T n)
{
    return WritePhys(pa, src, n);
}

NTSTATUS CsWritePhysMdl(ULONG64 pa, const void* src, SIZE_T n)
{
    if (!src || !n || !PhysRamOk(pa, n))
        return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if ((pa & 0xFFF) || n > 0x1000)
        return STATUS_INVALID_PARAMETER;
    return WritePhysMdl(pa, src, n);
}

NTSTATUS CsWritePhysNoWin(ULONG64 pa, const void* src, SIZE_T n)
{
    if (!src || !n)
        return STATUS_INVALID_PARAMETER;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    if (off + n > 0x1000)
        return STATUS_INVALID_PARAMETER;
    return WritePhysMdl(pa, src, n);
}

ULONG64 KernelCr3(void)
{
    const ULONG64 cur = __readcr3() & kPhysMask;
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, L"PsInitialSystemProcess");
    auto* p = reinterpret_cast<PEPROCESS*>(MmGetSystemRoutineAddress(&n));
    if (!p || !MmIsAddressValid(p) || !*p)
        return cur;
    ULONG off = cs_map_slot_g.kern_dtb_off;
    if (!off)
        off = cs_map_slot_g.dtb_off;
    if (!off)
        return cur;
    const ULONG64 k = ReadEprocessQword(*p, off);
    return k ? k : cur;
}

DECLSPEC_ALIGN(4096) UCHAR g_split_pt[4][4096];
BOOLEAN g_split_used[4];

struct OwnedLeaf {
    ULONG64 pa;
    PUCHAR va;
};

OwnedLeaf g_owned[12];
ULONG g_nowned;

extern "C" void CsOwnRegister(PVOID va, ULONG64 pa)
{
    if (!va || !pa)
        return;
    const ULONG64 page = pa & ~0xFFFull;
    if (!page)
        return;
    for (ULONG i = 0; i < g_nowned; ++i) {
        if (g_owned[i].pa == page)
            return;
    }
    if (g_nowned >= 12)
        return;
    g_owned[g_nowned].pa = page;
    g_owned[g_nowned].va = static_cast<PUCHAR>(va);
    g_nowned += 1;
}

BOOLEAN CsOwnRead(ULONG64 pa, PVOID dst, SIZE_T n)
{
    if (!dst || !n)
        return FALSE;
    const ULONG64 page = pa & ~0xFFFull;
    const SIZE_T off = static_cast<SIZE_T>(pa & 0xFFF);
    if (off + n > 0x1000)
        return FALSE;
    for (ULONG i = 0; i < g_nowned; ++i) {
        if (g_owned[i].pa != page)
            continue;
        RtlCopyMemory(dst, g_owned[i].va + off, n);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN TakeSplitPt(ULONG64* pa, ULONG64** va, ULONG* idx)
{
    if (!pa || !va || !idx)
        return FALSE;
    for (ULONG i = 0; i < 4; ++i) {
        if (g_split_used[i])
            continue;
        RtlZeroMemory(g_split_pt[i], 4096);
        ULONG64 p = 0;
        if (!NT_SUCCESS(CsOwnPa(g_split_pt[i], &p)))
            continue;
        CsOwnRegister(g_split_pt[i], p);
        *idx = i;
        *pa = p;
        *va = reinterpret_cast<ULONG64*>(g_split_pt[i]);
        return TRUE;
    }
    return FALSE;
}

void FlushVaRange(ULONG64 va, ULONG64 span)
{
    const ULONG64 base = va & ~(span - 1);
    for (ULONG64 off = 0; off < span; off += 0x1000ull)
        __invlpg(reinterpret_cast<PVOID>(base + off));
}

NTSTATUS CsSplitLarge(ULONG64 va)
{
    ULONG64 cr3 = __readcr3() & kPhysMask;
    ULONG64 pa = 0;
    ULONG64 pte_pa = 0;
    ULONG64 pte = 0;
    NTSTATUS st = TranslatePte(cr3, va, &pa, &pte_pa, &pte);
    if (!NT_SUCCESS(st) && va > kUserVaMax) {
        const ULONG64 kcr3 = KernelCr3();
        if (kcr3 && kcr3 != cr3) {
            cr3 = kcr3;
            st = TranslatePte(cr3, va, &pa, &pte_pa, &pte);
        }
    }
    if (!NT_SUCCESS(st))
        return st;
    if (!(pte & kLarge))
        return STATUS_SUCCESS;

    const ULONG64 pml4 = cr3 & kPhysMask;
    ULONG64 e4 = 0;
    st = ReadPhys(pml4 + ((va >> 39) & 0x1FF) * 8, &e4, 8);
    if (!NT_SUCCESS(st) || !(e4 & kPresent))
        return NT_SUCCESS(st) ? STATUS_NOT_FOUND : st;
    ULONG64 e3 = 0;
    const ULONG64 e3_pa = (e4 & kPhysMask) + ((va >> 30) & 0x1FF) * 8;
    st = ReadPhys(e3_pa, &e3, 8);
    if (!NT_SUCCESS(st) || !(e3 & kPresent))
        return NT_SUCCESS(st) ? STATUS_NOT_FOUND : st;

    if (e3 & kLarge) {
        ULONG64 pd_pa = 0;
        ULONG64* pd = nullptr;
        ULONG pd_i = 0;
        if (!TakeSplitPt(&pd_pa, &pd, &pd_i))
            return STATUS_NO_MEMORY;
        ULONG64 proto = (e3 & ~kPhysMask) | kPresent | kLarge;
        const ULONG64 base = e3 & k1gMask;
        for (ULONG i = 0; i < 512; ++i)
            pd[i] = proto | (base + static_cast<ULONG64>(i) * 0x200000ull);
        ULONG64 new_e3 = kPresent | (pd_pa & kPhysMask);
        if (e3 & 2)
            new_e3 |= 2;
        if (e3 & 4)
            new_e3 |= 4;
        if (e3 & kNx)
            new_e3 |= kNx;
        st = WritePhysNoWin(e3_pa, &new_e3, 8);
        if (!NT_SUCCESS(st))
            return st;
        g_split_used[pd_i] = TRUE;
        FlushVaRange(va, 0x40000000ull);
        st = ReadPhys(e3_pa, &e3, 8);
        if (!NT_SUCCESS(st) || !(e3 & kPresent) || (e3 & kLarge))
            return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }

    ULONG64 e2 = 0;
    const ULONG64 e2_pa = (e3 & kPhysMask) + ((va >> 21) & 0x1FF) * 8;
    st = ReadPhys(e2_pa, &e2, 8);
    if (!NT_SUCCESS(st) || !(e2 & kPresent))
        return NT_SUCCESS(st) ? STATUS_NOT_FOUND : st;
    if (!(e2 & kLarge))
        return STATUS_SUCCESS;

    ULONG64 pt_pa = 0;
    ULONG64* pt = nullptr;
    ULONG pt_i = 0;
    if (!TakeSplitPt(&pt_pa, &pt, &pt_i))
        return STATUS_NO_MEMORY;
    ULONG64 proto = (e2 & ~kPhysMask & ~kLarge) | kPresent;
    const ULONG64 base_pfn = (e2 & k2mMask) >> 12;
    for (ULONG i = 0; i < 512; ++i)
        pt[i] = proto | ((base_pfn + i) << 12);
    ULONG64 new_e2 = kPresent | (pt_pa & kPhysMask);
    if (e2 & 2)
        new_e2 |= 2;
    if (e2 & 4)
        new_e2 |= 4;
    if (e2 & kNx)
        new_e2 |= kNx;
    st = WritePhysNoWin(e2_pa, &new_e2, 8);
    if (!NT_SUCCESS(st))
        return st;
    g_split_used[pt_i] = TRUE;
    FlushVaRange(va, 0x200000ull);
    return STATUS_SUCCESS;
}

NTSTATUS CsTranslateVa(ULONG64 va, ULONG64* pa)
{
    const ULONG64 cur = __readcr3() & kPhysMask;
    NTSTATUS st = TranslateLeaf(cur, va, pa);
    if (NT_SUCCESS(st))
        return st;
    if (va <= kUserVaMax)
        return st;
    const ULONG64 kcr3 = KernelCr3();
    if (!kcr3 || kcr3 == cur)
        return st;
    return TranslateLeaf(kcr3, va, pa);
}

NTSTATUS CsPteClearNx(ULONG64 va)
{
    ULONG64 pa = 0;
    ULONG64 pte_pa = 0;
    ULONG64 pte = 0;
    ULONG64 cr3 = __readcr3() & kPhysMask;
    NTSTATUS st = TranslatePte(cr3, va, &pa, &pte_pa, &pte);
    if (!NT_SUCCESS(st) && va > kUserVaMax) {
        const ULONG64 kcr3 = KernelCr3();
        if (kcr3 && kcr3 != cr3)
            st = TranslatePte(kcr3, va, &pa, &pte_pa, &pte);
    }
    if (!NT_SUCCESS(st))
        return st;
    if (pte & kLarge)
        return STATUS_NOT_SUPPORTED;
    if (!(pte & kNx))
        return STATUS_SUCCESS;
    pte &= ~kNx;
    const NTSTATUS wst = WritePhysNoWin(pte_pa, &pte, 8);
    if (!NT_SUCCESS(wst))
        return wst;
    __invlpg(reinterpret_cast<PVOID>(va));
    return STATUS_SUCCESS;
}

NTSTATUS CsPteClearRw(ULONG64 va)
{
    ULONG64 pa = 0;
    ULONG64 pte_pa = 0;
    ULONG64 pte = 0;
    ULONG64 cr3 = __readcr3() & kPhysMask;
    NTSTATUS st = TranslatePte(cr3, va, &pa, &pte_pa, &pte);
    if (!NT_SUCCESS(st) && va > kUserVaMax) {
        const ULONG64 kcr3 = KernelCr3();
        if (kcr3 && kcr3 != cr3)
            st = TranslatePte(kcr3, va, &pa, &pte_pa, &pte);
    }
    if (!NT_SUCCESS(st))
        return st;
    if (pte & kLarge)
        return STATUS_NOT_SUPPORTED;
    if (!(pte & 2))
        return STATUS_SUCCESS;
    pte &= ~2ull;
    const NTSTATUS wst = WritePhysNoWin(pte_pa, &pte, 8);
    if (!NT_SUCCESS(wst))
        return wst;
    __invlpg(reinterpret_cast<PVOID>(va));
    return STATUS_SUCCESS;
}

NTSTATUS CsOwnPa(PVOID va, ULONG64* pa)
{
    if (!va || !pa)
        return STATUS_INVALID_PARAMETER;
    *pa = 0;
    (void)*static_cast<volatile UCHAR*>(va);
    const PHYSICAL_ADDRESS a = MmGetPhysicalAddress(va);
    if (a.QuadPart >= 0x1000)
        *pa = static_cast<ULONG64>(a.QuadPart);
    if (*pa)
        return STATUS_SUCCESS;
    return CsTranslateVa(reinterpret_cast<ULONG64>(va), pa);
}

NTSTATUS CsPteSetPfn(ULONG64 va, ULONG64 new_pa)
{
    if (!va || !new_pa)
        return STATUS_INVALID_PARAMETER;
    ULONG64 cr3 = __readcr3() & kPhysMask;
    ULONG64 pa = 0;
    ULONG64 pte_pa = 0;
    ULONG64 pte = 0;
    NTSTATUS st = TranslatePte(cr3, va, &pa, &pte_pa, &pte);
    if (!NT_SUCCESS(st) && va > kUserVaMax) {
        const ULONG64 kcr3 = KernelCr3();
        if (kcr3 && kcr3 != cr3)
            st = TranslatePte(kcr3, va, &pa, &pte_pa, &pte);
    }
    if (!NT_SUCCESS(st))
        return st;
    if (pte & kLarge)
        return STATUS_NOT_SUPPORTED;
    pte = (pte & ~kPhysMask) | (new_pa & kPhysMask);
    pte |= kPresent;
    st = WritePhysNoWin(pte_pa, &pte, 8);
    if (!NT_SUCCESS(st))
        return st;
    __invlpg(reinterpret_cast<PVOID>(va));
    return STATUS_SUCCESS;
}

NTSTATUS CsResolveCr3(PEPROCESS process, PVOID image_base, ULONG64 create_time)
{
    if (!process || !image_base)
        return STATUS_INVALID_PARAMETER;
    const HANDLE pid = PsGetProcessId(process);
    if (!create_time)
        create_time = static_cast<ULONG64>(PsGetProcessCreateTimeQuadPart(process));
    if (g_cr3.pid == pid && g_cr3.create_time == create_time && g_cr3.base == image_base
        && (g_cr3.user_dtb || g_cr3.kern_dtb))
        return STATUS_SUCCESS;

    const ULONG64 dtb = ReadEprocessQword(process, cs_map_slot_g.dtb_off);
    const ULONG64 user = ReadEprocessQword(process, cs_map_slot_g.user_dtb_off);
    const ULONG64 kern = ReadEprocessQword(process, cs_map_slot_g.kern_dtb_off);
    ULONG64 pick = 0;
    NTSTATUS last = STATUS_NOT_FOUND;
    BOOLEAN hit = FALSE;
    if (user) {
        last = ProbeCr3Mz(user, image_base, &hit);
        if (!NT_SUCCESS(last) && last != STATUS_NOT_FOUND)
            return last;
        if (NT_SUCCESS(last) && hit)
            pick = user;
    }
    if (!pick && kern && kern != user) {
        last = ProbeCr3Mz(kern, image_base, &hit);
        if (!NT_SUCCESS(last) && last != STATUS_NOT_FOUND)
            return last;
        if (NT_SUCCESS(last) && hit)
            pick = kern;
    }
    if (!pick && dtb && dtb != user && dtb != kern) {
        last = ProbeCr3Mz(dtb, image_base, &hit);
        if (!NT_SUCCESS(last) && last != STATUS_NOT_FOUND)
            return last;
        if (NT_SUCCESS(last) && hit)
            pick = dtb;
    }
    if (!pick) {
        RtlZeroMemory(&g_cr3, sizeof(g_cr3));
        return NT_SUCCESS(last) ? STATUS_NOT_FOUND : last;
    }
    const ULONG64 want_user = pick;
    const ULONG64 want_kern = kern ? kern : pick;
    if (g_cr3.pid == pid && g_cr3.create_time == create_time && g_cr3.base == image_base
        && g_cr3.user_dtb == want_user && g_cr3.kern_dtb == want_kern
        && (g_cr3.user_dtb || g_cr3.kern_dtb))
        return STATUS_SUCCESS;

    CacheCr3(pid, create_time, image_base, pick, want_kern);
    return STATUS_SUCCESS;
}

NTSTATUS CsCopyOut(PEPROCESS process, ULONG64 va, PVOID dst, SIZE_T bytes)
{
    if (!process || !dst || !bytes || !va)
        return STATUS_INVALID_PARAMETER;
    if (va > kUserVaMax || static_cast<ULONG64>(bytes) - 1ull > kUserVaMax - va)
        return STATUS_ACCESS_DENIED;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    PVOID image = CsProcessBase(process);
    if (!image)
        return STATUS_NOT_FOUND;
    const ULONG64 create = static_cast<ULONG64>(PsGetProcessCreateTimeQuadPart(process));
    const NTSTATUS rst = CsResolveCr3(process, image, create);
    if (!NT_SUCCESS(rst)) {
        CsWalkDropPid(PsGetProcessId(process));
        return rst;
    }
    return CopyRange(FALSE, va, dst, bytes);
}

NTSTATUS CsCopyIn(PEPROCESS process, ULONG64 va, PVOID src, SIZE_T bytes)
{
    if (!process || !src || !bytes || !va)
        return STATUS_INVALID_PARAMETER;
    if (va > kUserVaMax || static_cast<ULONG64>(bytes) - 1ull > kUserVaMax - va)
        return STATUS_ACCESS_DENIED;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    PVOID image = CsProcessBase(process);
    if (!image)
        return STATUS_NOT_FOUND;
    const ULONG64 create = static_cast<ULONG64>(PsGetProcessCreateTimeQuadPart(process));
    const NTSTATUS rst = CsResolveCr3(process, image, create);
    if (!NT_SUCCESS(rst)) {
        CsWalkDropPid(PsGetProcessId(process));
        return rst;
    }
    return CopyRange(TRUE, va, src, bytes);
}

#pragma code_seg()
