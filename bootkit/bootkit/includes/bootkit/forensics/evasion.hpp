#ifndef EVASION_HPP_
#define EVASION_HPP_

#include <bootkit/general.hpp>
#include <bootkit/interfaces.hpp>

BOOLEAN hide_module(EFI_HANDLE image_handle, VOID *image_base = nullptr);
void **hijack_event(UINT32 type, EFI_EVENT_NOTIFY hook, EFI_EVENT_NOTIFY *original);

#endif // EVASION_HPP_