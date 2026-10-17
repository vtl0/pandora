#ifndef MEMORY_HPP_
#define MEMORY_HPP_

#include <cstdint>

#define PT_INDEX 12
#define PD_INDEX 21
#define PDPT_INDEX 30
#define PML4_INDEX 39
#define PML5_INDEX 48
#define MAX_ENTRIES 512

#define ENTRY_PRESENT (1ULL << 0)
#define ENTRY_RW (1ULL << 1)
#define ENTRY_US (1ULL << 2)
#define ENTRY_PWT (1ULL << 3)
#define ENTRY_PCD (1ULL << 4)
#define ENTRY_A (1ULL << 5)
#define ENTRY_D (1ULL << 6)
#define ENTRY_PS (1ULL << 7)
#define ENTRY_G (1ULL << 8)
#define ENTRY_NX (1ULL << 63)
#define PT_PA_MASK (0x000FFFFFFFFFF000ULL)
#define PT_PROT_MASK (ENTRY_RW | ENTRY_US | ENTRY_NX | ENTRY_PWT | ENTRY_PCD | ENTRY_G)
#define PT_FLAGS_MASK (PT_PROT_MASK | ENTRY_PRESENT | ENTRY_A | ENTRY_D | ENTRY_PS)

#define PS_4K (1ULL << 12)
#define PS_2M (1ULL << 21)
#define PS_1G (1ULL << 30)

#define PROT_OP_SET 0
#define PROT_OP_AND 1
#define PROT_OP_OR 2

namespace pt {
  typedef uintptr_t (*allocator_fn)(void);
  inline uintptr_t page_offset;

  namespace reserved_pool {
    inline uintptr_t reserved_frames;
    inline size_t reserved_capacity;
    inline size_t reserved_used;
    uintptr_t get_next();
    EFI_STATUS init_pool(size_t count);
  } // namespace reserved_pool

  namespace kernel_managed_pool {
    struct kernel_brk {
      uintptr_t *brk_end;
      uintptr_t brk_limit;
    };

    inline kernel_brk linux_brk;

    uintptr_t get_next();
    bool init_pool(void *data);
  }

  uintptr_t new_frame();
  size_t frame_count(uintptr_t base, uintptr_t size, uint8_t level = 5);
  uintptr_t virt_to_phys(uintptr_t address);
  uintptr_t virt_to_phys_ex(uint64_t cr3, uintptr_t address);
  uintptr_t *try_safe_access_frame(uintptr_t addr);
  void set_page_offset(uintptr_t page_offset_base);
  bool set_page_prot(uintptr_t va, uintptr_t prot, size_t *page_size = nullptr,
                     bool invlpg = true, int set_mode = PROT_OP_SET);
  bool set_page_prot_ex(uint64_t cr3, uintptr_t va, uintptr_t prot,
                        size_t *page_size = nullptr, bool invlpg = true,
                        int set_mode = PROT_OP_SET);
  bool is_page_present(uintptr_t address, size_t *page_size = nullptr, uintptr_t *flags = nullptr);
  bool is_page_present_ex(uint64_t cr3, uintptr_t address, size_t *page_size = nullptr,
                          uintptr_t *flags = nullptr);
  bool mark_page_present(uintptr_t address, uintptr_t prot, bool invlpg = true);
  bool mark_page_present_ex(uint64_t cr3, uintptr_t va, uintptr_t pa, uintptr_t prot,
                            bool invlpg = true, size_t *mapped_size = nullptr);
  bool map_range(uintptr_t va, uintptr_t pa, size_t size, uintptr_t prot, bool invlpg = true,
                 uintptr_t va_clone_base = 0, bool use_clone_size = true);
  bool map_range_ex(uint64_t cr3, uintptr_t va, uintptr_t pa, size_t size, uintptr_t prot,
                    bool invlpg = true, uintptr_t va_clone_base = 0, bool use_clone_size = true);
  bool is_range_mapped(uintptr_t address, size_t size);
  bool is_range_mapped_ex(uint64_t cr3, uintptr_t address, size_t size);
  size_t mapped_range_from(uintptr_t address, uintptr_t *base = nullptr);
  size_t mapped_range_from_ex(uint64_t cr3, uintptr_t address, uintptr_t *base = nullptr);
  size_t unmapped_range_from(uintptr_t address, uintptr_t *base = nullptr);
  size_t unmapped_range_from_ex(uint64_t cr3, uintptr_t address, uintptr_t *base = nullptr);
} // namespace pt

#endif // MEMORY_HPP_