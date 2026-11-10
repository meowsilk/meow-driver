#pragma once

#if defined(_KERNEL_MODE) || defined(_NTDDK_)
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long long uint64_t;
#else
#include <stdint.h>
#endif

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4200)
#endif

static const uint32_t kCsVersion = 11;
static const uint32_t kCsHidePhys = 1u << 0;
static const uint32_t kCsHideMmpfn = 1u << 1;
static const uint32_t kCsHideBugcheck = 1u << 2;
static const uint32_t kCsHideEtwPph = 1u << 3;
static const uint32_t kCsHideEtwCkcl = 1u << 4;
static const uint32_t kCsHideEtwSys = 1u << 5;
static const uint32_t kCsHideAcl = 1u << 6;
static const uint32_t kCsHideImage = 1u << 7;
static const uint32_t kCsHideStub = 1u << 8;
static const uint32_t kCsHideKdp = 1u << 9;
static const uint32_t kCsHideDbg = 1u << 10;
static const uint32_t kCsMaxBatch = 512;
static const uint32_t kCsOutputBytes = 0xC0000;
static const uint32_t kCsScratchBytes = 0x20000;
static const uint32_t kCsOutLimit = kCsOutputBytes - kCsScratchBytes;
static const uint32_t kCsModsBytes = 0x10000;
static const uint32_t kCsDirBytes = 0x1000;
static const uint32_t kCsMarkBytes = 0x1000;
static const uint32_t kCsScrubPages = 32;
static const uint64_t kCsMapMagic = 0xA17C3E90D52B84F6ULL;

enum cs_op : uint32_t {
    cs_op_idle = 0,
    cs_op_read = 1,
    cs_op_write = 2,
    cs_op_base = 3,
    cs_op_shutdown = 4,
};

enum cs_stage : uint32_t {
    cs_stage_ok = 0,
    cs_stage_init = 1,
    cs_stage_channel = 2,
    cs_stage_attach = 3,
    cs_stage_grab = 4,
    cs_stage_map = 5,
    cs_stage_hide = 6,
    cs_stage_batch = 7,
    cs_stage_eneio = 8,
    cs_stage_pg = 9,
    cs_stage_place = 10,
    cs_stage_pte = 11,
    cs_stage_entry = 12,
    cs_stage_traces = 13,
    cs_stage_ready = 14,
};

struct cs_err {
    int32_t status;
    uint32_t stage;
    uint32_t index;
    uint32_t reserved;
    uint64_t detail;
};

struct cs_diag {
    uint32_t stage;
    int32_t status;
    uint32_t line;
    uint32_t reserved;
    char file[24];
    char what[96];
};

static const uint32_t kCsPteCap = 64;

struct cs_pte_ent {
    uint64_t va;
    uint64_t pte_pa;
};

struct cs_map_slot {
    uint64_t magic;
    cs_diag diag;
    uint32_t dtb_off;
    uint32_t kern_dtb_off;
    uint32_t user_dtb_off;
    uint32_t generation;
    uint64_t mapper_pid;
    uint64_t section_handle;
    uint64_t pulse_handle;
    uint64_t done_handle;
    uint64_t mm_pfn_database;
    uint64_t image_base;
    uint64_t image_size;
    uint32_t mmpfn_stride;
    uint32_t section_base_off;
    uint32_t peb_off;
    uint32_t peb_image_off;
    uint32_t mmpfn_pte_frame_off;
    uint32_t kthread_syscall_off;
    uint32_t etw_silo_rva;
    uint32_t ssdt_rva;
    uint32_t kisyscall_rva;
    uint64_t stub_pid;
    uint64_t stub_create;
    uint64_t ntos_base;
    uint32_t hide_mask;
    uint32_t hide_ok;
    uint32_t hide_err;
    uint32_t hide_step;
    uint32_t hide_nhooks;
    uint32_t hide_sys_miss;
    uint32_t syscall_id[9];
    uint32_t kdp_rva;
    uint32_t dbgprint_list_rva;
    uint32_t kdp_select_rva;
    uint32_t kibugcheck_rva;
    uint32_t scrub_request;
    uint32_t scrub_stamp;
    uint32_t scrub_unloaded_rva;
    uint32_t scrub_last_rva;
    uint32_t scrub_stride;
    uint32_t scrub_status;
    uint64_t scrub_wiped;
    wchar_t scrub_name[64];
    uint32_t scrub_pages;
    uint32_t scrub_pad;
    uint32_t stack_shred_scanned;
    uint32_t stack_shred_rewritten;
    uint64_t touch_va;
    uint32_t touch_request;
    uint32_t touch_status;
    uint32_t ethread_start_off;
    uint32_t ethread_win32_off;
    uint32_t delay_rva;
    uint32_t flush_rva;
    uint32_t wait_rva;
    uint32_t wait_span;
    uint32_t pte_count;
    uint32_t pte_pad;
    cs_pte_ent pte[kCsPteCap];
};

struct cs_scrub_page {
    uint64_t pa;
    uint64_t mark;
};

static inline uint64_t cs_page_mark(const void* page, uint32_t n)
{
    const unsigned char* p = (const unsigned char*)page;
    uint64_t h = 0xCBF29CE484222325ull;
    for (uint32_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x100000001B3ull;
    }
    return h;
}

struct cs_perf {
    uint64_t batch_qpc;
    uint64_t qpc_freq;
    uint32_t batch_count;
    int32_t last_status;
};

struct cs_entry {
    uint32_t op;
    int32_t status;
    uint64_t pid;
    uint64_t address;
    uint64_t size;
    uint64_t out_off;
};

struct cs_ctrl {
    uint32_t magic;
    uint32_t version;
    volatile uint32_t request_seq;
    volatile uint32_t response_seq;
    int32_t last_status;
    uint32_t flags;
    uint64_t um_pid;
    uint64_t um_create_time;
    uint64_t um_view;
    uint64_t section_handle;
    uint64_t pulse_handle;
    uint64_t done_handle;
    cs_err err;
    cs_diag diag;
    cs_perf perf;
    uint32_t batch_count;
    uint32_t output_used;
    cs_entry entries[512];
};

static const uint32_t kCsCtrlBytes = sizeof(cs_ctrl);
static const uint32_t kCsSectionBytes = sizeof(cs_ctrl) + kCsOutputBytes;

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
