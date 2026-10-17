#ifndef VMLINUX_HPP_
#define VMLINUX_HPP_

#include <bootkit/arch/abi.hpp>

#include <cstdint>

#define X86_64_KERNEL_VA_MIN 0xffffffff80000000
#define X86_64_KERNEL_VA_MAX 0xffffffffc0000000

namespace vmlinux {
  inline uintptr_t base;
  inline uintptr_t end;
  inline uintptr_t base_pa;
  inline uintptr_t kallsyms_base;
  inline uintptr_t __init_scratch_end;
  inline bool config_have_arch_prel32_relocations;

  typedef int(SYSV_ABI *initcall_t)(void);
  typedef int(SYSV_ABI *printk_t)(const char *fmt, ...);
  typedef int(SYSV_ABI *access_process_vm_t)(void *tsk, unsigned long addr, void *buf,
                                             int len, unsigned int gup_flags);

  inline printk_t printk;
} // namespace vmlinux

#endif // VMLINUX_HPP_