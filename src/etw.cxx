#include <ntifs.h>
#include "etw.hxx"
#include "hide.hxx"
#include "kapi_bind.hxx"

void CsEtwInstall(void)
{
    CsHideFail(kCsHideEtwSys, STATUS_NOT_SUPPORTED, 0);
    CsHideFail(kCsHideEtwPph, STATUS_NOT_SUPPORTED, 0);
    CsHideFail(kCsHideEtwCkcl, STATUS_NOT_SUPPORTED, 0);
}
