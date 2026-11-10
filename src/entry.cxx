#include <ntddk.h>
#include <intrin.h>
#include "channel.hxx"
#include "kapi.hxx"
#include "kapi_bind.hxx"

#pragma function(memset)
#pragma function(memcpy)

extern "C" void* memset(void* dst, int c, size_t n)
{
    __stosb(static_cast<unsigned char*>(dst), static_cast<unsigned char>(c), n);
    return dst;
}

extern "C" void* memcpy(void* dst, const void* src, size_t n)
{
    __movsb(static_cast<unsigned char*>(dst), static_cast<const unsigned char*>(src), n);
    return dst;
}

cs_kapi g_kapi = { kCsKapiMagic };

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    UNREFERENCED_PARAMETER(driver);
    UNREFERENCED_PARAMETER(registry);

    return CsChannelStart(nullptr);
}
