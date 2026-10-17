#ifndef VMLINUX_HOOKS_HPP_
#define VMLINUX_HOOKS_HPP_

#include <bootkit/arch/abi.hpp>
#include <bootkit/hooking/jmp_hooking.hpp>

#include <cstdint>

namespace hooks::vmlinux {
  void kaslr_cr3_mov();
  void reset_early_page_tables();
  void NAKED init_mem_mapping_mov_cr3();
  void SYSV_ABI set_pmd(uintptr_t pmdp, uintptr_t pmdval);
  int SYSV_ABI first_initcall_hook();

  bool do_hook_cleanup_highmap();
  bool do_hook_initcalls();
  bool do_setup_and_use_brk_pool(uintptr_t stext_va, uintptr_t stext_pa, uintptr_t efi_page_tables);

  inline jmp_hook_ctx kaslr_mov_hook_ctx;
  inline jmp_hook_ctx reset_early_page_tables_hook_ctx;
  inline jmp_hook_ctx init_mem_mapping_mov_cr3_ctx;
  inline jmp_hook_ctx set_pmd_ctx;

  inline uint64_t efi_pgt;
  inline uint64_t early_top_pgt;
  inline uint64_t startup_64_original_rsp;
  inline uint64_t startup_64_original_rbp;
  inline uint64_t startup_64_original_rax;
  inline uint64_t startup_64_original_rsi;
  inline uint64_t startup_64_original_r15;
  inline uint64_t init_mem_mapping_original_regs[16];
  inline uint8_t init_mem_mapping_cr3_reg;
  inline uintptr_t *common_startup_64;
  inline uintptr_t original_first_initcall;
  inline uintptr_t first_initcall_table;
} // namespace hooks::vmlinux

#endif // VMLINUX_HOOKS_HPP_