#include <ntifs.h>
#include <intrin.h>
#include "channel.hxx"
#include "memory.hxx"
#include "hide.hxx"
#include "kapi_bind.hxx"

cs_ctrl* g_channel = nullptr;
cs_map_slot cs_map_slot_g = { kCsMapMagic, {} };

static PVOID g_view = nullptr;
static PVOID g_section_obj = nullptr;
static PKEVENT g_pulse_ev = nullptr;
static PKEVENT g_done_ev = nullptr;
static PEPROCESS g_client = nullptr;
static BOOLEAN g_own_view = FALSE;
static uint32_t g_bind_magic = 0;
static uint64_t g_bind_pid = 0;
static uint64_t g_bind_create = 0;
static volatile LONG g_session_gen = 0;
static volatile LONG g_pulse_on = 0;
static HANDLE g_keep_section = nullptr;
static HANDLE g_keep_pulse = nullptr;
static HANDLE g_keep_done = nullptr;
static UCHAR* g_zero_page = nullptr;
static UCHAR* g_mark_page = nullptr;

static void DropClient(void)
{
    if (g_client) {
        ObDereferenceObject(g_client);
        g_client = nullptr;
    }
    g_bind_magic = 0;
    g_bind_pid = 0;
    g_bind_create = 0;
}

static void CloseKeep(void)
{
    if (g_keep_section) {
        ZwClose(g_keep_section);
        g_keep_section = nullptr;
    }
    if (g_keep_pulse) {
        ZwClose(g_keep_pulse);
        g_keep_pulse = nullptr;
    }
    if (g_keep_done) {
        ZwClose(g_keep_done);
        g_keep_done = nullptr;
    }
}

static void ReleaseChannel(void)
{
    if (g_own_view && g_view)
        MmUnmapViewInSystemSpace(g_view);
    g_view = nullptr;
    g_channel = nullptr;
    g_own_view = FALSE;
    if (g_section_obj) {
        ObDereferenceObject(g_section_obj);
        g_section_obj = nullptr;
    }
    if (g_pulse_ev) {
        ObDereferenceObject(g_pulse_ev);
        g_pulse_ev = nullptr;
    }
    if (g_done_ev) {
        ObDereferenceObject(g_done_ev);
        g_done_ev = nullptr;
    }
    CloseKeep();
    DropClient();
    InterlockedIncrement(&g_session_gen);
}

static void Ack(cs_ctrl* ctrl)
{
    ctrl->response_seq = ctrl->request_seq;
    if (g_done_ev)
        KeSetEvent(g_done_ev, IO_NO_INCREMENT, FALSE);
}

static void WriteErr(cs_ctrl* c, int32_t status, uint32_t stage, uint32_t index, uint64_t detail)
{
    if (!c)
        return;
    c->err.status = status;
    c->err.stage = stage;
    c->err.index = index;
    c->err.detail = detail;
    c->last_status = status;
    cs_diag keep{};
    CsPhysDiagFill(&keep);
    if (CsPhysDiagOk(&keep))
        c->diag = keep;
}

static BOOLEAN BindHolds(const cs_ctrl* probe)
{
    if (!probe || !probe->magic || probe->version != kCsVersion)
        return FALSE;
    if (!probe->um_pid || !probe->um_create_time || probe->batch_count > kCsMaxBatch)
        return FALSE;
    if (!g_bind_pid)
        return TRUE;
    return probe->magic == g_bind_magic && probe->um_pid == g_bind_pid;
}

static BOOLEAN BindClientGone(void)
{
    if (!g_client || !g_bind_pid)
        return TRUE;
    PEPROCESS p = nullptr;
    const NTSTATUS st = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(g_bind_pid), &p);
    if (!NT_SUCCESS(st) || !p)
        return TRUE;
    const BOOLEAN gone = static_cast<uint64_t>(PsGetProcessCreateTimeQuadPart(p)) != g_bind_create;
    ObDereferenceObject(p);
    return gone;
}

static NTSTATUS RefProcessHandle(PEPROCESS proc, HANDLE h, ACCESS_MASK access, POBJECT_TYPE type, PVOID* out, HANDLE* keep)
{
    *out = nullptr;
    if (keep)
        *keep = nullptr;
    if (!proc || !h || !out)
        return STATUS_INVALID_PARAMETER;

    HANDLE local = h;
    HANDLE opened = nullptr;
    NTSTATUS st = STATUS_SUCCESS;
    if (PsGetCurrentProcess() != proc) {
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
        CLIENT_ID cid{};
        cid.UniqueProcess = PsGetProcessId(proc);
        st = ZwOpenProcess(&opened, PROCESS_DUP_HANDLE, &oa, &cid);
        if (!NT_SUCCESS(st) || !opened)
            return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
        st = ZwDuplicateObject(opened, h, NtCurrentProcess(), &local, 0, 0, DUPLICATE_SAME_ACCESS);
        ZwClose(opened);
        if (!NT_SUCCESS(st) || !local)
            return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }

    st = ObReferenceObjectByHandle(local, access, type, KernelMode, out, nullptr);
    if (local != h)
        ZwClose(local);
    if (!NT_SUCCESS(st))
        return st;
    if (!keep)
        return STATUS_SUCCESS;

    HANDLE kernel = nullptr;
    st = ObOpenObjectByPointer(*out, OBJ_KERNEL_HANDLE, nullptr, access, type, KernelMode, &kernel);
    const ULONG_PTR kernel_bit = static_cast<ULONG_PTR>(1) << (sizeof(void*) * 8 - 1);
    if (!NT_SUCCESS(st) || !kernel || (reinterpret_cast<ULONG_PTR>(kernel) & kernel_bit) == 0) {
        if (kernel)
            ZwClose(kernel);
        ObDereferenceObject(*out);
        *out = nullptr;
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }
    *keep = kernel;
    return STATUS_SUCCESS;
}

static NTSTATUS InstallSession(PEPROCESS owner, HANDLE sh, HANDLE ph, HANDLE dh)
{
    if (!owner || !sh || !ph || !dh)
        return STATUS_INVALID_PARAMETER;

    PVOID section = nullptr;
    PVOID pulse = nullptr;
    PVOID done = nullptr;
    HANDLE ks = nullptr;
    HANDLE kp = nullptr;
    HANDLE kd = nullptr;
    NTSTATUS st = RefProcessHandle(owner, sh, SECTION_MAP_READ | SECTION_MAP_WRITE, nullptr, &section, &ks);
    if (NT_SUCCESS(st))
        st = RefProcessHandle(owner, ph, EVENT_MODIFY_STATE, *ExEventObjectType, &pulse, &kp);
    if (NT_SUCCESS(st))
        st = RefProcessHandle(owner, dh, EVENT_MODIFY_STATE, *ExEventObjectType, &done, &kd);
    if (!NT_SUCCESS(st) || !section || !pulse || !done || !ks || !kp || !kd) {
        if (kd)
            ZwClose(kd);
        if (kp)
            ZwClose(kp);
        if (ks)
            ZwClose(ks);
        if (done)
            ObDereferenceObject(done);
        if (pulse)
            ObDereferenceObject(pulse);
        if (section)
            ObDereferenceObject(section);
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }

    PVOID view = nullptr;
    SIZE_T view_size = kCsSectionBytes;
    st = MmMapViewInSystemSpace(section, &view, &view_size);
    if (!NT_SUCCESS(st) || !view || view_size < kCsSectionBytes) {
        ZwClose(kd);
        ZwClose(kp);
        ZwClose(ks);
        ObDereferenceObject(done);
        ObDereferenceObject(pulse);
        ObDereferenceObject(section);
        return NT_SUCCESS(st) ? STATUS_BUFFER_TOO_SMALL : st;
    }

    ReleaseChannel();
    g_keep_section = ks;
    g_keep_pulse = kp;
    g_keep_done = kd;

    auto* ctrl = static_cast<cs_ctrl*>(view);
    const uint32_t keep_magic = ctrl->magic;
    const uint64_t keep_pid = ctrl->um_pid;
    const uint64_t keep_create = ctrl->um_create_time;
    const uint64_t keep_view = ctrl->um_view;
    if (!keep_magic) {
        RtlZeroMemory(view, kCsCtrlBytes);
    } else {
        ctrl->request_seq = 0;
        ctrl->response_seq = 0;
        ctrl->batch_count = 0;
        ctrl->output_used = 0;
    }
    ctrl->magic = keep_magic;
    ctrl->version = kCsVersion;
    ctrl->um_pid = keep_pid;
    ctrl->um_create_time = keep_create;
    ctrl->um_view = keep_view;
    ctrl->section_handle = reinterpret_cast<uint64_t>(sh);
    ctrl->pulse_handle = reinterpret_cast<uint64_t>(ph);
    ctrl->done_handle = reinterpret_cast<uint64_t>(dh);
    g_section_obj = section;
    g_view = view;
    g_channel = ctrl;
    g_own_view = TRUE;
    g_pulse_ev = static_cast<PKEVENT>(pulse);
    g_done_ev = static_cast<PKEVENT>(done);
    InterlockedIncrement(&g_session_gen);
    return STATUS_SUCCESS;
}

static NTSTATUS TryBind(void)
{
    if (!BindHolds(g_channel))
        return STATUS_REVISION_MISMATCH;

    if (cs_map_slot_g.mapper_pid && g_channel->um_pid == cs_map_slot_g.mapper_pid)
        return STATUS_ACCESS_DENIED;

    PEPROCESS client = nullptr;
    const NTSTATUS st = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(g_channel->um_pid), &client);
    if (!NT_SUCCESS(st) || !client)
        return NT_SUCCESS(st) ? STATUS_NOT_FOUND : st;
    const uint64_t created = static_cast<uint64_t>(PsGetProcessCreateTimeQuadPart(client));
    g_channel->um_create_time = created;
    g_client = client;
    g_bind_magic = g_channel->magic;
    g_bind_pid = g_channel->um_pid;
    g_bind_create = created;
    WriteErr(g_channel, static_cast<int32_t>(STATUS_SUCCESS), cs_stage_attach, 0, g_bind_pid);
    return STATUS_SUCCESS;
}

static BOOLEAN ProcessBatch(cs_ctrl* ctrl)
{
    if (!BindHolds(ctrl)) {
        WriteErr(ctrl, static_cast<int32_t>(STATUS_ACCESS_DENIED), cs_stage_batch, 0, 0);
        Ack(ctrl);
        return FALSE;
    }

    BOOLEAN stop = FALSE;
    NTSTATUS first_fail = STATUS_SUCCESS;
    uint32_t fail_i = 0;
    ctrl->output_used = 0;
    const uint32_t n = ctrl->batch_count;
    PUCHAR out_base = reinterpret_cast<PUCHAR>(ctrl) + kCsCtrlBytes;
    LARGE_INTEGER qpf{};
    const LARGE_INTEGER t0 = KeQueryPerformanceCounter(&qpf);

    PEPROCESS process = nullptr;
    uint64_t cur_pid = 0;
    BOOLEAN cr3_ok = FALSE;

    for (uint32_t i = 0; i < n; ++i) {
        cs_entry* e = &ctrl->entries[i];
        NTSTATUS one = STATUS_SUCCESS;

        if (e->op == cs_op_shutdown) {
            stop = TRUE;
            ctrl->entries[i].status = static_cast<int32_t>(STATUS_SUCCESS);
            continue;
        }

        if (!process || e->pid != cur_pid) {
            if (process) {
                ObDereferenceObject(process);
                process = nullptr;
            }
            cur_pid = e->pid;
            cr3_ok = FALSE;
            const NTSTATUS lst = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(e->pid), &process);
            if (!NT_SUCCESS(lst) || !process) {
                CsWalkDropPid(reinterpret_cast<HANDLE>(e->pid));
                process = nullptr;
                one = STATUS_NOT_FOUND;
                ctrl->entries[i].status = static_cast<int32_t>(one);
                if (NT_SUCCESS(first_fail)) {
                    first_fail = one;
                    fail_i = i;
                    WriteErr(ctrl, static_cast<int32_t>(one), cs_stage_batch, i, e->address);
                }
                continue;
            }
        }

        if (e->op == cs_op_base) {
            if (e->out_off > kCsOutLimit - 8)
                one = STATUS_BUFFER_TOO_SMALL;
            else {
                const ULONG64 base = reinterpret_cast<ULONG64>(CsProcessBase(process));
                if (!base)
                    one = STATUS_NOT_FOUND;
                else
                    *reinterpret_cast<ULONG64*>(out_base + e->out_off) = base;
            }
        } else if (e->op == cs_op_write || e->op == cs_op_read) {
            if (!cr3_ok) {
                PVOID image = CsProcessBase(process);
                const ULONG64 create = static_cast<ULONG64>(PsGetProcessCreateTimeQuadPart(process));
                if (!image) {
                    one = STATUS_NOT_FOUND;
                } else {
                    one = CsResolveCr3(process, image, create);
                    if (!NT_SUCCESS(one))
                        CsWalkDropPid(reinterpret_cast<HANDLE>(e->pid));
                    else
                        cr3_ok = TRUE;
                }
            }
            if (NT_SUCCESS(one)) {
                if (e->size > kCsOutLimit || e->out_off > kCsOutLimit - e->size) {
                    one = STATUS_BUFFER_TOO_SMALL;
                } else if (e->op == cs_op_write) {
                    one = CsCopyIn(process, e->address, out_base + e->out_off, static_cast<SIZE_T>(e->size));
                } else {
                    one = CsCopyOut(process, e->address, out_base + e->out_off, static_cast<SIZE_T>(e->size));
                }
            }
        } else {
            one = STATUS_INVALID_DEVICE_REQUEST;
        }

        ctrl->entries[i].status = static_cast<int32_t>(one);
        if (!NT_SUCCESS(one) && NT_SUCCESS(first_fail)) {
            first_fail = one;
            fail_i = i;
            WriteErr(ctrl, static_cast<int32_t>(one), cs_stage_batch, i, e->address);
        }
    }

    if (process)
        ObDereferenceObject(process);

    const LARGE_INTEGER t1 = KeQueryPerformanceCounter(nullptr);
    if (qpf.QuadPart > 0 && t1.QuadPart >= t0.QuadPart) {
        ctrl->perf.qpc_freq = static_cast<uint64_t>(qpf.QuadPart);
        ctrl->perf.batch_qpc = static_cast<uint64_t>(t1.QuadPart - t0.QuadPart);
    } else {
        ctrl->perf.qpc_freq = 0;
        ctrl->perf.batch_qpc = 0;
    }
    ctrl->last_status = static_cast<int32_t>(first_fail);
    if (NT_SUCCESS(first_fail))
        WriteErr(ctrl, static_cast<int32_t>(STATUS_SUCCESS), cs_stage_batch, n, 0);
    else
        ctrl->err.index = fail_i;
    Ack(ctrl);
    return stop;
}

static WCHAR Fold(WCHAR c)
{
    if (c >= L'A' && c <= L'Z')
        return static_cast<WCHAR>(c - L'A' + L'a');
    return c;
}

static BOOLEAN NameHas(const UNICODE_STRING* name, const WCHAR* needle)
{
    if (!name || !name->Buffer || !name->Length || !needle || !needle[0])
        return FALSE;
    const USHORT nchars = name->Length / sizeof(WCHAR);
    if (!nchars || nchars > 260 || !MmIsAddressValid(name->Buffer))
        return FALSE;
    WCHAR got[261];
    RtlCopyMemory(got, name->Buffer, name->Length);
    got[nchars] = 0;
    SIZE_T nlen = 0;
    while (needle[nlen])
        nlen += 1;
    if (!nlen || nlen > nchars)
        return FALSE;
    for (USHORT i = 0; i + nlen <= nchars; ++i) {
        BOOLEAN same = TRUE;
        for (SIZE_T k = 0; k < nlen; ++k) {
            if (Fold(got[i + k]) != Fold(needle[k])) {
                same = FALSE;
                break;
            }
        }
        if (same)
            return TRUE;
    }
    return FALSE;
}

static NTSTATUS ZeroUnloaded(BOOLEAN* found)
{
    if (found)
        *found = FALSE;
    const uint32_t stride = cs_map_slot_g.scrub_stride;
    if (stride < sizeof(UNICODE_STRING) || stride > 0x80)
        return STATUS_INVALID_PARAMETER;
    if (!cs_map_slot_g.ntos_base || !cs_map_slot_g.scrub_unloaded_rva || !cs_map_slot_g.scrub_name[0])
        return STATUS_NOT_FOUND;
    const ULONG64 global = cs_map_slot_g.ntos_base + cs_map_slot_g.scrub_unloaded_rva;
    if (!MmIsAddressValid(reinterpret_cast<PVOID>(global)))
        return STATUS_NOT_FOUND;
    const ULONG64 table = *reinterpret_cast<ULONG64*>(global);
    if (!table || !MmIsAddressValid(reinterpret_cast<PVOID>(table)))
        return STATUS_NOT_FOUND;
    BOOLEAN hit = FALSE;
    for (ULONG i = 0; i < 50; ++i) {
        auto* entry = reinterpret_cast<PUCHAR>(table + static_cast<ULONG64>(i) * stride);
        if (!MmIsAddressValid(entry))
            break;
        auto* name = reinterpret_cast<UNICODE_STRING*>(entry);
        if (!NameHas(name, cs_map_slot_g.scrub_name))
            continue;
        if (name->Buffer && name->Length && name->Length <= 512 && MmIsAddressValid(name->Buffer))
            RtlZeroMemory(name->Buffer, name->Length);
        RtlZeroMemory(entry, stride);
        hit = TRUE;
    }
    if (found)
        *found = hit;
    return STATUS_SUCCESS;
}

static BOOLEAN BlockedPa(uint64_t pa)
{
    const uint64_t page = pa & ~0xFFFull;
    if (!page)
        return TRUE;
    UCHAR stack_local = 0;
    const PHYSICAL_ADDRESS stk = MmGetPhysicalAddress(&stack_local);
    if (stk.QuadPart && (static_cast<uint64_t>(stk.QuadPart) & ~0xFFFull) == page)
        return TRUE;
    if (g_zero_page) {
        const PHYSICAL_ADDRESS z = MmGetPhysicalAddress(g_zero_page);
        if (z.QuadPart && (static_cast<uint64_t>(z.QuadPart) & ~0xFFFull) == page)
            return TRUE;
    }
    if (g_mark_page) {
        const PHYSICAL_ADDRESS m = MmGetPhysicalAddress(g_mark_page);
        if (m.QuadPart && (static_cast<uint64_t>(m.QuadPart) & ~0xFFFull) == page)
            return TRUE;
    }
    if (g_channel) {
        auto* list = reinterpret_cast<UCHAR*>(g_channel) + sizeof(cs_ctrl);
        const PHYSICAL_ADDRESS c = MmGetPhysicalAddress(list);
        if (c.QuadPart && (static_cast<uint64_t>(c.QuadPart) & ~0xFFFull) == page)
            return TRUE;
        const PHYSICAL_ADDRESS tail = MmGetPhysicalAddress(list + (kCsScrubPages * sizeof(cs_scrub_page) - 1));
        if (tail.QuadPart && (static_cast<uint64_t>(tail.QuadPart) & ~0xFFFull) == page)
            return TRUE;
    }
    const ULONG64 base = cs_map_slot_g.image_base;
    const ULONG64 size = cs_map_slot_g.image_size;
    if (base < 0xFFFF800000000000ull || size < 0x1000ull || size > 0x100000ull)
        return FALSE;
    const ULONG64 first = base & ~0xFFFull;
    const ULONG64 span = (size + 0xFFFull) & ~0xFFFull;
    if (span < size || first + span <= first)
        return FALSE;
    for (ULONG64 va = first; va < first + span; va += 0x1000) {
        const PHYSICAL_ADDRESS a = MmGetPhysicalAddress(reinterpret_cast<PVOID>(va));
        if (a.QuadPart && (static_cast<uint64_t>(a.QuadPart) & ~0xFFFull) == page)
            return TRUE;
    }
    return FALSE;
}

static NTSTATUS WipeImage(uint64_t* wiped)
{
    if (wiped)
        *wiped = 0;
    const uint32_t count = cs_map_slot_g.scrub_pages;
    if (!count)
        return STATUS_SUCCESS;
    if (!g_channel || count > kCsScrubPages)
        return STATUS_INVALID_PARAMETER;
    const uint64_t need = sizeof(cs_ctrl) + static_cast<uint64_t>(count) * sizeof(cs_scrub_page);
    if (need > kCsSectionBytes)
        return STATUS_INVALID_PARAMETER;
    auto* list = reinterpret_cast<cs_scrub_page*>(reinterpret_cast<UCHAR*>(g_channel) + sizeof(cs_ctrl));
    uint64_t pages = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint64_t pa = list[i].pa;
        if (!pa || (pa & 0xFFF))
            continue;
        if (!g_mark_page || !g_zero_page || !NT_SUCCESS(CsReadPhys(pa, g_mark_page, kCsMarkBytes)))
            continue;
        if (cs_page_mark(g_mark_page, kCsMarkBytes) != list[i].mark) {
            pages += 1;
            continue;
        }
        if (BlockedPa(pa))
            continue;
        const NTSTATUS wst = CsWritePhysMdl(pa, g_zero_page, kCsMarkBytes);
        if (wst == STATUS_ACCESS_DENIED)
            continue;
        if (!NT_SUCCESS(wst)) {
            if (wiped)
                *wiped = pages;
            return STATUS_UNSUCCESSFUL;
        }
        pages += 1;
    }
    if (wiped)
        *wiped = pages;
    return pages == count ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static void PublishScrub(NTSTATUS st, uint64_t wiped, uint32_t slot)
{
    cs_map_slot_g.scrub_status = static_cast<uint32_t>(st);
    cs_map_slot_g.scrub_wiped = wiped;
    cs_map_slot_g.scrub_request = 0;
    if (g_channel) {
        g_channel->last_status = static_cast<int32_t>(st);
        g_channel->err.status = static_cast<int32_t>(st);
        g_channel->err.stage = cs_stage_traces;
        g_channel->err.index = slot;
        g_channel->err.detail = wiped;
    }
    if (g_done_ev)
        KeSetEvent(g_done_ev, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS TouchByte(uint64_t va)
{
    if (va < 0xFFFF800000000000ull)
        return STATUS_INVALID_PARAMETER;
    const UCHAR byte = *reinterpret_cast<volatile UCHAR*>(va);
    (void)byte;
    return STATUS_SUCCESS;
}

static BOOLEAN OnPulse()
{
    if (cs_map_slot_g.touch_request) {
        const NTSTATUS st = TouchByte(cs_map_slot_g.touch_va);
        cs_map_slot_g.touch_status = static_cast<uint32_t>(st);
        cs_map_slot_g.touch_request = 0;
        if (!cs_map_slot_g.scrub_request && g_done_ev)
            KeSetEvent(g_done_ev, IO_NO_INCREMENT, FALSE);
    }
    if (cs_map_slot_g.scrub_request) {
        BOOLEAN slot = FALSE;
        const NTSTATUS ust = ZeroUnloaded(&slot);
        uint64_t wiped = 0;
        const NTSTATUS wst = WipeImage(&wiped);

        const NTSTATUS sst = (NT_SUCCESS(ust) || ust == STATUS_NOT_FOUND) ? wst : ust;
        PublishScrub(sst, wiped, slot ? 1u : 0u);
        return FALSE;
    }
    if (!g_channel)
        return FALSE;
    if (g_client && (BindClientGone() || !BindHolds(g_channel)))
        DropClient();
    if (!g_client) {
        const NTSTATUS bst = TryBind();
        if (!NT_SUCCESS(bst) && g_channel->request_seq != g_channel->response_seq) {
            WriteErr(g_channel, static_cast<int32_t>(bst), cs_stage_attach, 0, g_channel->um_pid);
            Ack(g_channel);
        }
    }
    if (g_client && BindHolds(g_channel) && g_channel->request_seq != g_channel->response_seq)
        return ProcessBatch(g_channel);
    return FALSE;
}

static NTSTATUS StampThread(HANDLE thread)
{
    if (!cs_map_slot_g.ethread_start_off || !cs_map_slot_g.delay_rva || !cs_map_slot_g.ntos_base)
        return STATUS_NOT_SUPPORTED;
    PVOID obj = nullptr;
    const NTSTATUS st = ObReferenceObjectByHandle(thread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &obj, nullptr);
    if (!NT_SUCCESS(st) || !obj)
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    const ULONG64 dest = cs_map_slot_g.ntos_base + cs_map_slot_g.delay_rva;
    auto* base = static_cast<UCHAR*>(obj);
    *reinterpret_cast<ULONG64*>(base + cs_map_slot_g.ethread_start_off) = dest;
    if (cs_map_slot_g.ethread_win32_off)
        *reinterpret_cast<ULONG64*>(base + cs_map_slot_g.ethread_win32_off) = dest;
    ObDereferenceObject(obj);
    return STATUS_SUCCESS;
}

static void ShredStack(void)
{
    const ULONG64 base = cs_map_slot_g.image_base;
    const ULONG64 size = cs_map_slot_g.image_size;
    if (!base || base < 0xFFFF800000000000ull || size < 0x1000 || size > 0x100000)
        return;
    const ULONG64 fake = cs_map_slot_g.ntos_base + cs_map_slot_g.delay_rva;
    if (!fake || fake < 0xFFFF800000000000ull)
        return;
    const ULONG64 lo = base;
    const ULONG64 hi = base + size;

    const ULONG64 rsp = reinterpret_cast<ULONG64>(_AddressOfReturnAddress()) & ~7ull;
    const ULONG64 page = rsp & ~0xFFFull;
    if (!MmIsAddressValid(reinterpret_cast<PVOID>(page)))
        return;
    uint32_t scanned = 0;
    uint32_t rewritten = 0;
    for (ULONG64 va = rsp; va + 8 <= page + 0x1000; va += 8) {
        volatile ULONG64* slot = reinterpret_cast<volatile ULONG64*>(va);
        const ULONG64 v = *slot;
        scanned += 1;
        if (v >= lo && v < hi) {
            *slot = fake;
            rewritten += 1;
        }
    }
    cs_map_slot_g.stack_shred_scanned = scanned;
    cs_map_slot_g.stack_shred_rewritten = rewritten;
}

static BOOLEAN MapperGone(void)
{
    if (!cs_map_slot_g.mapper_pid)
        return TRUE;
    PEPROCESS owner = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(cs_map_slot_g.mapper_pid), &owner)) || !owner)
        return TRUE;
    ObDereferenceObject(owner);
    return FALSE;
}

static void PulseThread(PVOID)
{

    ShredStack();
    uint32_t idle = 0;
    while (g_pulse_on && g_pulse_ev) {
        LARGE_INTEGER tick{};
        tick.QuadPart = -10000000LL;
        const NTSTATUS wst = KeWaitForSingleObject(g_pulse_ev, Executive, KernelMode, FALSE, &tick);
        if (!g_pulse_on)
            break;
        if (wst == STATUS_SUCCESS) {
            idle = 0;
            if (OnPulse()) {
                InterlockedExchange(&g_pulse_on, 0);
                ReleaseChannel();
                CsWalkReset();
                break;
            }
            continue;
        }
        if (wst != STATUS_TIMEOUT)
            break;

        if (MapperGone()) {
            idle += 1;
            if (idle >= 3)
                break;
        } else {
            idle = 0;
        }
    }
    InterlockedExchange(&g_pulse_on, 0);
    ReleaseChannel();
    CsWalkReset();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static BOOLEAN BindScratch()
{
    if (!g_view)
        return FALSE;
    auto* base = static_cast<UCHAR*>(g_view) + kCsCtrlBytes + (kCsOutputBytes - kCsScratchBytes);
    g_zero_page = base;
    g_mark_page = base + kCsMarkBytes;
    return TRUE;
}

static NTSTATUS CsMakeChannel(void)
{
    const HANDLE sh = reinterpret_cast<HANDLE>(cs_map_slot_g.section_handle);
    const HANDLE ph = reinterpret_cast<HANDLE>(cs_map_slot_g.pulse_handle);
    const HANDLE dh = reinterpret_cast<HANDLE>(cs_map_slot_g.done_handle);
    if (!cs_map_slot_g.mapper_pid || !sh || !ph || !dh)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS mapper = nullptr;
    NTSTATUS st = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(cs_map_slot_g.mapper_pid), &mapper);
    if (!NT_SUCCESS(st) || !mapper)
        return NT_SUCCESS(st) ? STATUS_NOT_FOUND : st;

    st = InstallSession(mapper, sh, ph, dh);
    ObDereferenceObject(mapper);
    if (NT_SUCCESS(st) && !BindScratch())
        return STATUS_INSUFFICIENT_RESOURCES;
    return st;
}

NTSTATUS CsChannelStart(PDRIVER_OBJECT)
{
    CsWalkReset();
    const NTSTATUS init = CsWalkInit();
    if (!NT_SUCCESS(init))
        return init;
    const NTSTATUS pte_prep = CsPrepImagePteViews();
    if (!NT_SUCCESS(pte_prep))
        return pte_prep;

    if (g_channel || g_pulse_ev || g_section_obj)
        return STATUS_ALREADY_REGISTERED;

    NTSTATUS st = CsMakeChannel();
    if (!NT_SUCCESS(st))
        return st;

    CsHideStart();

    if (InterlockedCompareExchange(&g_pulse_on, 1, 0) != 0) {
        ReleaseChannel();
        CsWalkReset();
        return STATUS_ALREADY_REGISTERED;
    }
    HANDLE thread = nullptr;
    st = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, PulseThread, nullptr);
    if (!NT_SUCCESS(st) || !thread) {
        InterlockedExchange(&g_pulse_on, 0);
        ReleaseChannel();
        CsWalkReset();
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }
    st = StampThread(thread);
    if (!NT_SUCCESS(st)) {
        InterlockedExchange(&g_pulse_on, 0);
        if (g_pulse_ev)
            KeSetEvent(g_pulse_ev, IO_NO_INCREMENT, FALSE);
        ZwWaitForSingleObject(thread, FALSE, nullptr);
        ZwClose(thread);
        ReleaseChannel();
        CsWalkReset();
        return st;
    }
    ZwClose(thread);
    cs_map_slot_g.generation = 1;
    return STATUS_SUCCESS;
}
