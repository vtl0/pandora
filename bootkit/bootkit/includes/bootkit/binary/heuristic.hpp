#ifndef HEURISTIC_HPP_
#define HEURISTIC_HPP_

#include <bootkit/arch/x86/x86.hpp>
#include <bootkit/linux/kallsyms.hpp>

#include <cstdint>

namespace heuristic {
  uintptr_t retroactive_find_pe_base(uintptr_t addr);
  uintptr_t get_event_signal_queue();
  bool is_enter_kernel(uintptr_t c, uint8_t *what_reg);
  uintptr_t find_startup_64_va_jmp(uintptr_t code, uintptr_t *mov_cr3_address, bool *is_old_pattern);
  uintptr_t retroactive_find_elf_base(uintptr_t code);
  uintptr_t retroactive_find_map_base(uintptr_t va);
  uintptr_t bruteforce_find_vmlinux_base(uintptr_t base, uintptr_t limit);
  uintptr_t forward_find_map_end(uintptr_t va);
  uintptr_t find_next_map_with_prot(uintptr_t va, uintptr_t desired_prot);
  uintptr_t find_init_mem_mapping_cr3_mov(uintptr_t init_mem_mapping, uintptr_t early_memtest,
                                          uint8_t *what_reg);
  uintptr_t find_set_pmd_used_by_cleanup_highmap(uintptr_t cleanup_highmap);
  bool shim_find_system_services_hook_functions(uintptr_t shim_base, size_t shim_size,
                                                uintptr_t *hook, uintptr_t *unhook);
  bool is_valid_ascii_string(const char *s, size_t *size = nullptr);
  bool is_valid_kallsyms(uintptr_t num_syms_addr, kallsyms::ks *ksms);
  bool is_valid_kallsyms_ex(uintptr_t num_syms_addr, kallsyms::ks *ksms, int alignment);
  bool is_valid_kallsyms_offsets(int32_t *syms, unsigned int count, uint32_t traits,
                                 uintptr_t kallsyms_relative_base = 0);
  bool is_kallsyms_markers_valid(uint32_t *markers, unsigned int count);
  bool is_kallsyms_token_index_valid(uint16_t *token_index, uint16_t token_table_size);
  bool kallsyms_are_offsets_before_num_syms(kallsyms::ks *lo, uintptr_t num_syms_addr);
  bool kallsyms_are_offsets_post_token_index(kallsyms::ks *lo, uint32_t *traits, int alignment);
  size_t get_kallsyms_names_size(uint8_t *names, unsigned int num_syms, bool *uleb128);
  uint16_t get_kallsyms_token_table_size(const char *token_table);
  bool is_grub(uintptr_t image_base, size_t image_size);
  bool is_uki(uintptr_t image_base, size_t image_size);
  bool is_systemd_stub(uintptr_t image_base, size_t image_size);
  bool is_systemd_boot(uintptr_t image_base, size_t image_size);
  bool is_bootmgfw(uintptr_t image_base, size_t image_size);
  bool is_winload(uintptr_t image_base, size_t image_size);
  bool is_bzimage(uintptr_t image_base, size_t image_size);
  bool is_veracrypt(uintptr_t image_base, size_t image_size);
  bool is_shimx64(uintptr_t image_base, size_t image_size);
}; // namespace heuristic

#endif // HEURISTIC_HPP_