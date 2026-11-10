#pragma once

#include <ntddk.h>
#include "protocol.hxx"

#ifdef __cplusplus
extern "C" {
#endif

void CsHideMark(uint32_t bit, BOOLEAN ok);
void CsHideFail(uint32_t bit, NTSTATUS st, uint32_t step);
void CsHideStart(void);

#ifdef __cplusplus
}
#endif
