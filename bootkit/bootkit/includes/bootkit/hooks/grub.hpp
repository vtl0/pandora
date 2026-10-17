#ifndef GRUB_HOOKS_HPP_
#define GRUB_HOOKS_HPP_

#include <bootkit/arch/abi.hpp>
#include <bootkit/grub/grubx64.hpp>
#include <bootkit/hooking/jmp_hooking.hpp>

using grub_dl_t = grubx64::grub_dl_t;
using grub_dl_t_2_14 = grubx64::grub_dl_t_2_14;
using gcry_err_code_t = grubx64::gcry_err_code_t;

namespace hooks::grub {
  inline jmp_hook_ctx grub_dl_load_core_noinit_ctx;
  inline jmp_hook_ctx grub_cryptodisk_setkey_ctx;

  grub_dl_t SYSV_ABI grub_dl_load_core_noinit(void *addr, uintptr_t size);
  gcry_err_code_t SYSV_ABI grub_cryptodisk_setkey_hook(void *dev, uint8_t *key,
                                                                  uintptr_t keysize);
}

#endif // GRUB_HOOKS_HPP_