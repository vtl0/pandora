#ifndef EFI_HOOKS_HPP_
#define EFI_HOOKS_HPP_

extern "C" {
#include <Uefi.h>

#include <Protocol/DevicePath.h>
}

namespace hooks::efi {
  inline EFI_IMAGE_LOAD original_LoadImage;
  inline EFI_IMAGE_START original_StartImage;
  inline EFI_LOCATE_PROTOCOL original_LocateProtocol;
  inline EFI_SET_MEMORY_ATTRIBUTES original_SetMemoryAttributes;

  inline uintptr_t uki_image_base;
  inline uintptr_t uki_image_end;

  EFI_STATUS EFIAPI LoadImage(BOOLEAN BootPolicy, EFI_HANDLE ParentImageHandle,
                              EFI_DEVICE_PATH_PROTOCOL *DevicePath, VOID *SourceBuffer,
                              UINTN SourceSize, EFI_HANDLE *ImageHandle);
  EFI_STATUS EFIAPI LocateProtocol(EFI_GUID *Protocol, VOID *Registration, VOID **Interface);
  EFI_STATUS EFIAPI SetMemoryAttributes(EFI_MEMORY_ATTRIBUTE_PROTOCOL *This,
                                        EFI_PHYSICAL_ADDRESS BaseAddress, UINT64 Length,
                                        UINT64 Attributes);
}

#endif // EFI_HOOKS_HPP_