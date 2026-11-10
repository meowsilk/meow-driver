#pragma once

#include <ntddk.h>
#include "protocol.hxx"

#ifdef __cplusplus
extern "C" {
#endif

extern cs_ctrl* g_channel;

NTSTATUS CsChannelStart(PDRIVER_OBJECT driver);

#ifdef __cplusplus
}
#endif
