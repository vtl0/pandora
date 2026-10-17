#ifndef BINARY_IDENTIFIER_HPP_
#define BINARY_IDENTIFIER_HPP_

#include <cstdint>

extern "C" {
#include <Uefi.h>
}

enum image_type {
  UNKNOWN_IMAGE,
  GRUB,
  SYSTEMD_BOOT,
  BZIMAGE,
  SYSTEMD_STUB,
  SYSTEMD_STUB_UKI,
  STUB_UKI,
  BOOTMGFW,
  WINLOAD,
  VERACRYPT,
  SHIMLOADER
};

image_type identify_image(EFI_HANDLE image, uintptr_t *p_base = nullptr, size_t *p_size = nullptr);

#endif // BINARY_IDENTIFIER_HPP_