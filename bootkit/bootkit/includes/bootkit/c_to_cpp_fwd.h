#ifndef C_TO_CPP_FWD_H
#define C_TO_CPP_FWD_H

#include <Uefi.h>

#ifdef __cplusplus
extern "C" {
#endif

EFI_STATUS EFIAPI uefi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table);
EFI_STATUS EFIAPI uefi_exit(EFI_HANDLE image_handle);

#ifdef __cplusplus
}
#endif

#endif // C_TO_CPP_FWD_H