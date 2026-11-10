#include <ntifs.h>
#include "hide.hxx"
#include "memory.hxx"
#include "etw.hxx"
#include "kapi_bind.hxx"

extern cs_map_slot cs_map_slot_g;

void CsHideMark(uint32_t bit, BOOLEAN ok)
{
    if (!bit)
        return;
    cs_map_slot_g.hide_mask |= bit;
    if (ok)
        cs_map_slot_g.hide_ok |= bit;
    else
        cs_map_slot_g.hide_ok &= ~bit;
}

void CsHideFail(uint32_t bit, NTSTATUS st, uint32_t step)
{
    CsHideMark(bit, FALSE);
    if (!NT_SUCCESS(st) && !cs_map_slot_g.hide_err)
        cs_map_slot_g.hide_err = static_cast<uint32_t>(st);
    if (step && !cs_map_slot_g.hide_step)
        cs_map_slot_g.hide_step = step;
}

void CsHideStart(void)
{
    CsPhysSelfTest();
    cs_diag phys{};
    CsPhysDiagFill(&phys);
    CsHideMark(kCsHidePhys, CsPhysDiagOk(&phys));
    CsEtwInstall();
}
