#ifndef GLOBALS_HPP_
#define GLOBALS_HPP_

extern "C" {
#include <Uefi.h>
}

enum system_type {
  NONE,
  LINUX,
  WINDOWS,
  OTHER
};

enum boot_state {
  GRUB_LOADED = (1 << 0),
  SYSTEMD_BOOT_LOADED = (1 << 1),
  SYSTEMD_STUB_LOADED = (1 << 2),
  UKI_LOADED = (1 << 3),
  BZIMAGE_LOADED = (1 << 4),
  VMLINUX_LOADED = (1 << 5),
  BOOTMGFW_LOADED = (1 << 6),
  WINLOAD_LOADED = (1 << 7),
  VERACRYPT_LOADED = (1 << 8),
  KERNEL_MANAGED_FRAME_POOL_AVAILABLE = (1 << 9),
  POST_EXIT_BOOT_SERVICES = (1 << 30),
  POST_VIRTUAL_ADDRESS_CHANGE = (1 << 31)
};

namespace g {
  inline EFI_SYSTEM_TABLE *st;
  inline EFI_RUNTIME_SERVICES *rt;
  inline EFI_BOOT_SERVICES *bs;
  inline EFI_HANDLE image_handle;

  inline UINTN phys_map_count;
  inline UINTN descriptor_size;
  inline EFI_MEMORY_DESCRIPTOR *uefi_phys_maps;
  inline EFI_PHYSICAL_ADDRESS driver_pa;
  inline uintptr_t driver_va;
  inline size_t driver_len;

  inline system_type target_system;
  inline int state;
} // namespace g

#endif // GLOBALS_HPP_