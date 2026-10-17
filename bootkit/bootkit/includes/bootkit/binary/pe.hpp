#ifndef PE_HPP_
#define PE_HPP_

#include <cstdint>

extern "C" {
#include <IndustryStandard/PeImage.h>
}

namespace pe {
  uintptr_t get_export_address(const uintptr_t base, const char *name);
  bool get_section(uintptr_t base, const char *name, uintptr_t *section_base,
                   uintptr_t *section_size);
  uintptr_t get_entry_point(const uintptr_t base);
  bool get_code_section(uintptr_t base, uintptr_t *section_base, uintptr_t *section_size);
  bool relocate(uintptr_t from, uintptr_t to, size_t size, uint64_t from_cr3);
  bool fix_prot(uintptr_t va, bool keep_unnecessary_writable = true);
  bool hide(uintptr_t va);
} // namespace pe

#endif // PE_HPP_