# meow-driver

Windows x64 kernel-mode driver built to be mapped into `ntoskrnl` by an external
manual mapper instead of being loaded through the service manager.

There is no INF, no service entry, no `DriverEntry` registration and no import
descriptor: the entry point starts a request loop over a shared section and the
image performs every kernel call through a function table the loader fills in
before the first instruction runs.

- zero imports, so the image has no import table for a scanner to walk
- no tagged pool, no driver object, no device, no symbolic link
- all kernel APIs reached through `g_kapi`, a pointer array handed over by the mapper
- physical-memory read/write, per-process VA translation, batch requests of up to 512 operations
- scrub path that removes the image name from `MmUnloadedDrivers` and zeroes pages the loader marks as ours
- pulse thread that stamps its own `ETHREAD` start address to an ntoskrnl routine, shreds image addresses out of its stack page, and retires itself when the mapper process disappears

## Layout

```
meow-driver/
  meow-driver.vcxproj
  include/
    protocol.hxx       shared ABI: map slot, control block, entries, stages
    kapi.hxx           kernel API table layout
    kapi_bind.hxx      names bound to table indices
    kapi_unbind.hxx    names released back to the real prototypes
    channel.hxx        request loop entry
    memory.hxx         physical read/write and translation surface
    hide.hxx           post-map self checks
    etw.hxx            ETW stage hooks
    hde64.hxx          length disassembler
  src/
    entry.cxx          DriverEntry, freestanding memset/memcpy
    channel.cxx        section, events, pulse thread, batching, scrub
    memory.cxx         MDL, page-table and window paths, CR3 cache
    hide.cxx           hide stage driver
    etw.cxx            ETW stage
    hde64.cxx          length disassembler
```

Sources use the `.cxx`/`.hxx` extensions so the driver does not collide with
CRT headers of the same name.

## Loader contract

The mapper places the image, then finds `cs_map_slot_g` by its magic
(`kCsMapMagic`) inside the mapped pages and fills it in before calling
`DriverEntry`. The slot carries:

| field | meaning |
|---|---|
| `mapper_pid` | process that owns the section and events |
| `section_handle`, `pulse_handle`, `done_handle` | handles the mapper created in its own process |
| `ntos_base` | kernel base, used for every RVA the driver needs |
| `dtb_off`, `kern_dtb_off`, `user_dtb_off` | page-table offsets in the target build |
| `mmpfn_stride`, `mmpfn_pte_frame_off`, `mm_pfn_database` | PFN database geometry |
| `section_base_off`, `peb_off`, `peb_image_off` | EPROCESS/PEB offsets |
| `ethread_start_off`, `ethread_win32_off`, `delay_rva` | thread stamping |
| `scrub_unloaded_rva`, `scrub_stride`, `scrub_name` | unloaded-driver list scrub |
| `image_base`, `image_size`, `pte[]`, `pte_count` | the driver's own mapping |
| `hide_mask`, `hide_ok`, `hide_err` | stage results published back to the loader |

`g_kapi` (`kCsKapiMagic`) must point at `cs_kapi_count` resolved routines, in the
order listed in `include/kapi.hxx`.

## Protocol

The control block `cs_ctrl` sits at the start of the section, followed by
`kCsOutputBytes` of response and scratch space.

A request is: fill `entries[0..batch_count)`, bump `request_seq`, set the pulse
event. The driver validates the sender, runs the batch, writes per-entry status
into `cs_entry::status`, publishes the first failure in `cs_err`, sets
`response_seq` and signals the done event.

Operations: `cs_op_read`, `cs_op_write`, `cs_op_base`, `cs_op_shutdown`, up to
`kCsMaxBatch` per batch. `kCsVersion` must match the loader's copy.

## Design notes

- `DriverEntry` skips `ExInitializeDriverRuntime` on purpose: that inline emits an
  `RtlGetVersion` import and an image outside the loaded module list with any import
  run is classified as headerless executable.
- No pool allocation anywhere. MDL storage, the page-table page, the mapped window
  and the scratch pages are static, page aligned.
- Physical writes try the pre-mapped window, then an MDL built over the target PFN,
  then a PTE path that needs no window.
- Reads run through the caller's CR3, cached per PID and process create time, and
  fall back to the PFN database when the stored root is a decoy.
- The pulse thread waits in one second ticks, never forever, so a vanished loader
  cannot leave the image running on memory the manager may recycle.
- Scrub requests are page-checked (`BlockedPa`) before any write, so the driver
  cannot zero its own stack, channel or code.

## Build

Requirements: Visual Studio 2022 or newer with the C++ workload, Windows Driver Kit
10.0.28000, x64 host tools.

```
msbuild meow-driver.vcxproj /p:Configuration=Release /p:Platform=x64 /m
```

Output: `build/bin/Release/meow-driver.sys`, 22016 bytes with an empty import
directory. A mapped image is not loaded by the kernel loader, so the file does not
need a signature the loader would check; running it through DSE or a test-signing
boot is the loader's problem, not this project's.

## Disclaimer

Kernel research and testing only. Do not run this on a machine you do not own.
