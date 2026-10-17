#include <bootkit/arch/x86/memory.hpp>
#include <bootkit/arch/x86/x86.hpp>
#include <bootkit/arch/x86/msr.hpp>
#include <bootkit/general.hpp>
#include <bootkit/linux/vmlinux.hpp>

extern "C" {
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
}

uintptr_t pt::virt_to_phys(uintptr_t address)
{
  return virt_to_phys_ex(AsmReadCr3(), address);
}

uintptr_t pt::virt_to_phys_ex(uint64_t cr3, uintptr_t address)
{
  uint64_t cr4;
  uintptr_t *pml5;
  uintptr_t *pml4;
  uintptr_t *pdpt;
  uintptr_t *pd;
  uintptr_t *pt;
  uintptr_t pml5e;
  uintptr_t pml4e;
  uintptr_t pdpte;
  uintptr_t pde;
  uintptr_t pte;

  cr4 = AsmReadCr4();
  cr3 &= ~(PS_4K - 1);
  if (cr4 & CR4_LA57) {
    pml5 = try_safe_access_frame(cr3);
    pml5e = pml5[(address >> PML5_INDEX) & (MAX_ENTRIES - 1)];
    if (!(pml5e & ENTRY_PRESENT))
      return 0;

    pml4 = try_safe_access_frame(pml5e & PT_PA_MASK);
  }
  else
    pml4 = try_safe_access_frame(cr3);

  pml4e = pml4[(address >> PML4_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pml4e & ENTRY_PRESENT))
    return 0;

  pdpt = try_safe_access_frame(pml4e & PT_PA_MASK);
  pdpte = pdpt[(address >> PDPT_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pdpte & ENTRY_PRESENT))
    return 0;

  // 1GB
  if (pdpte & ENTRY_PS)
    return (pdpte & PT_PA_MASK) | (address & (PS_1G - 1));

  pd = try_safe_access_frame(pdpte & PT_PA_MASK);
  pde = pd[(address >> PD_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pde & ENTRY_PRESENT))
    return 0;

  // 2MB
  if (pde & ENTRY_PS)
    return (pde & PT_PA_MASK) | (address & (PS_2M - 1));

  pt = try_safe_access_frame(pde & PT_PA_MASK);
  pte = pt[(address >> PT_INDEX) & (MAX_ENTRIES - 1)];

  if (!(pte & ENTRY_PRESENT))
    return 0;

  return (pte & PT_PA_MASK) | (address & (PS_4K - 1));
}

uintptr_t *pt::try_safe_access_frame(uintptr_t addr)
{
  if (page_offset)
    return reinterpret_cast<uintptr_t *>(addr + page_offset);
  return reinterpret_cast<uintptr_t *>(addr);
}

void pt::set_page_offset(uintptr_t page_offset_base)
{
  page_offset = page_offset_base;
}

bool pt::set_page_prot(uintptr_t va, uintptr_t prot, size_t *page_size, bool invlpg, int set_mode)
{
  return set_page_prot_ex(AsmReadCr3(), va, prot, page_size, invlpg, set_mode);
}

bool pt::set_page_prot_ex(uint64_t cr3, uintptr_t va, uintptr_t prot, size_t *page_size,
                          bool invlpg, int set_mode)
{
  uintptr_t cr4;
  uintptr_t *pml5;
  uintptr_t *pml4;
  uintptr_t *pdpt;
  uintptr_t *pd;
  uintptr_t *pt;
  uintptr_t pml5e;
  uintptr_t pml4e;
  uintptr_t pdpte;
  uintptr_t pde;
  uintptr_t pte;

  auto set_prot = [&](uintptr_t entry) -> uintptr_t {
    if (set_mode == PROT_OP_SET)
      return (entry & ~PT_FLAGS_MASK) | (prot & PT_FLAGS_MASK) | ENTRY_PRESENT;
    else if (set_mode == PROT_OP_AND)
      return (entry & ((prot & PT_FLAGS_MASK) | (entry & ~PT_FLAGS_MASK))) | ENTRY_PRESENT;
    else if (set_mode == PROT_OP_OR)
      return entry | (prot & PT_FLAGS_MASK) | ENTRY_PRESENT;
    else
      return entry;
  };

  prot &= PT_PROT_MASK;
  if (!nxe_enabled())
    prot &= ~ENTRY_NX;
  cr4 = AsmReadCr4();
  cr3 &= ~(PS_4K - 1);
  if (cr4 & CR4_LA57) {
    pml5 = try_safe_access_frame(cr3);
    pml5e = pml5[(va >> PML5_INDEX) & (MAX_ENTRIES - 1)];
    if (!(pml5e & ENTRY_PRESENT))
      return false;

    pml5[(va >> PML5_INDEX) & (MAX_ENTRIES - 1)] = pml5e;
    pml4 = try_safe_access_frame(pml5e & PT_PA_MASK);
  }
  else
    pml4 = try_safe_access_frame(cr3);

  pml4e = pml4[(va >> PML4_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pml4e & ENTRY_PRESENT))
    return false;

  pml4[(va >> PML4_INDEX) & (MAX_ENTRIES - 1)] = pml4e;
  pdpt = try_safe_access_frame(pml4e & PT_PA_MASK);
  pdpte = pdpt[(va >> PDPT_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pdpte & ENTRY_PRESENT))
    return false;

  // 1GB
  if (pdpte & ENTRY_PS) {
    pdpt[(va >> PDPT_INDEX) & (MAX_ENTRIES - 1)] = set_prot(pdpte);
    if (invlpg)
      __asm__ volatile("invlpg (%0)" ::"r"(va) : "memory");

    if (page_size)
      *page_size = PS_1G;

    return true;
  }

  pdpt[(va >> PDPT_INDEX) & (MAX_ENTRIES - 1)] = pdpte;
  pd = try_safe_access_frame(pdpte & PT_PA_MASK);
  pde = pd[(va >> PD_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pde & ENTRY_PRESENT))
    return false;

  // 2MB
  if (pde & ENTRY_PS) {
    pd[(va >> PD_INDEX) & (MAX_ENTRIES - 1)] = set_prot(pde);
    if (invlpg)
      __asm__ volatile("invlpg (%0)" ::"r"(va) : "memory");

    if (page_size)
      *page_size = PS_2M;

    return true;
  }

  pd[(va >> PD_INDEX) & (MAX_ENTRIES - 1)] = pde;
  pt = try_safe_access_frame(pde & PT_PA_MASK);
  // 4KB
  pte = pt[(va >> PT_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pte & ENTRY_PRESENT))
    return false;

  pt[(va >> PT_INDEX) & (MAX_ENTRIES - 1)] = set_prot(pte);
  if (invlpg)
    __asm__ volatile("invlpg (%0)" ::"r"(va) : "memory");

  if (page_size)
    *page_size = PS_4K;

  return true;
}

bool pt::is_page_present(uintptr_t address, size_t *page_size, uintptr_t *flags)
{
  return is_page_present_ex(AsmReadCr3(), address, page_size, flags);
}

bool pt::is_page_present_ex(uint64_t cr3, uintptr_t address, size_t *page_size, uintptr_t *flags)
{
  uint64_t cr4;
  uintptr_t *pml5;
  uintptr_t *pml4;
  uintptr_t *pdpt;
  uintptr_t *pd;
  uintptr_t *pt;
  uintptr_t pml5e;
  uintptr_t pml4e;
  uintptr_t pdpte;
  uintptr_t pde;
  uintptr_t pte;

  cr4 = AsmReadCr4();
  cr3 &= ~(PS_4K - 1);
  if (cr4 & CR4_LA57) {
    pml5 = try_safe_access_frame(cr3);
    pml5e = pml5[(address >> PML5_INDEX) & (MAX_ENTRIES - 1)];
    if (!(pml5e & ENTRY_PRESENT))
      return false;

    pml4 = try_safe_access_frame(pml5e & PT_PA_MASK);
  }
  else
    pml4 = try_safe_access_frame(cr3);

  pml4e = pml4[(address >> PML4_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pml4e & ENTRY_PRESENT))
    return false;

  pdpt = try_safe_access_frame(pml4e & PT_PA_MASK);
  pdpte = pdpt[(address >> PDPT_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pdpte & ENTRY_PRESENT))
    return false;

  // 1GB
  if (pdpte & ENTRY_PS) {
    if (page_size)
      *page_size = PS_1G;
    if (flags)
      *flags = pdpte & PT_FLAGS_MASK;
    return true;
  }

  pd = try_safe_access_frame(pdpte & PT_PA_MASK);
  pde = pd[(address >> PD_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pde & ENTRY_PRESENT))
    return false;

  // 2MB
  if (pde & ENTRY_PS) {
    if (page_size)
      *page_size = PS_2M;
    if (flags)
      *flags = pde & PT_FLAGS_MASK;
    return true;
  }

  pt = try_safe_access_frame(pde & PT_PA_MASK);
  pte = pt[(address >> PT_INDEX) & (MAX_ENTRIES - 1)];

  if (page_size && (pte & ENTRY_PRESENT))
    *page_size = PS_4K;
  if (flags && (pte & ENTRY_PRESENT))
    *flags = pte & PT_FLAGS_MASK;

  return pte & ENTRY_PRESENT;
}

bool pt::mark_page_present(uintptr_t address, uintptr_t prot, bool invlpg)
{
  return mark_page_present_ex(AsmReadCr3(), address, address, prot, invlpg);
}

bool pt::mark_page_present_ex(uint64_t cr3, uintptr_t va, uintptr_t pa, uintptr_t prot, bool invlpg,
                              size_t *mapped_size)
{
  uintptr_t cr4;
  uintptr_t frame;
  uintptr_t *pml5;
  uintptr_t *pml4;
  uintptr_t *pdpt;
  uintptr_t *pd;
  uintptr_t *pt;
  uintptr_t pml5e;
  uintptr_t pml4e;
  uintptr_t pdpte;
  uintptr_t pde;
  uintptr_t pte;

  prot &= PT_PROT_MASK;
  if (!nxe_enabled())
    prot &= ~ENTRY_NX;
  cr4 = AsmReadCr4();
  cr3 &= ~(PS_4K - 1);
  if (cr4 & CR4_LA57) {
    pml5 = try_safe_access_frame(cr3);
    pml5e = pml5[(va >> PML5_INDEX) & (MAX_ENTRIES - 1)];
    if (!(pml5e & ENTRY_PRESENT)) {
      frame = new_frame();
      if (!frame)
        return false;
      pml5e = frame | ENTRY_PRESENT | ENTRY_RW;
    }
    pml5e &= ~ENTRY_NX;
    pml5[(va >> PML5_INDEX) & (MAX_ENTRIES - 1)] = pml5e;
    pml4 = try_safe_access_frame(pml5e & ~(PS_4K - 1));
  }
  else {
    pml4 = try_safe_access_frame(cr3);
  }

  pml4e = pml4[(va >> PML4_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pml4e & ENTRY_PRESENT)) {
    frame = new_frame();
    if (!frame)
      return false;
    pml4e = frame | ENTRY_PRESENT | ENTRY_RW;
  }

  pml4e &= ~ENTRY_NX;
  pml4[(va >> PML4_INDEX) & (MAX_ENTRIES - 1)] = pml4e;
  pdpt = try_safe_access_frame(pml4e & ~(PS_4K - 1));
  pdpte = pdpt[(va >> PDPT_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pdpte & ENTRY_PRESENT)) {
    frame = new_frame();
    if (!frame)
      return false;
    pdpte = frame | ENTRY_PRESENT | ENTRY_RW;
  }

  // 1GB
  if (pdpte & ENTRY_PS || (prot & ENTRY_PS && (pa & (PS_1G - 1)) == 0)) {
    pdpte = (pa & ~(PS_1G - 1)) | ENTRY_PRESENT | ENTRY_PS | prot;
    pdpt[(va >> PDPT_INDEX) & (MAX_ENTRIES - 1)] = pdpte;
    if (invlpg)
      __asm__ volatile("invlpg (%0)" ::"r"(va) : "memory");

    if (mapped_size)
      *mapped_size = PS_1G;

    return true;
  }

  pdpte &= ~ENTRY_NX;
  pdpt[(va >> PDPT_INDEX) & (MAX_ENTRIES - 1)] = pdpte;
  pd = try_safe_access_frame(pdpte & ~(PS_4K - 1));
  pde = pd[(va >> PD_INDEX) & (MAX_ENTRIES - 1)];
  if (!(pde & ENTRY_PRESENT)) {
    frame = new_frame();
    if (!frame)
      return false;
    pde = frame | ENTRY_PRESENT | ENTRY_RW;
  }

  // 2MB
  if (pde & ENTRY_PS || (prot & ENTRY_PS && (pa & (PS_2M - 1)) == 0)) {
    pde = (pa & ~(PS_2M - 1)) | ENTRY_PRESENT | ENTRY_PS | prot;
    pd[(va >> PD_INDEX) & (MAX_ENTRIES - 1)] = pde;
    if (invlpg)
      __asm__ volatile("invlpg (%0)" ::"r"(va) : "memory");

    if (mapped_size)
      *mapped_size = PS_2M;

    return true;
  }

  pde &= ~ENTRY_NX;
  pd[(va >> PD_INDEX) & (MAX_ENTRIES - 1)] = pde;
  pt = try_safe_access_frame(pde & ~(PS_4K - 1));
  // 4KB
  pte = (pa & ~(PS_4K - 1)) | ENTRY_PRESENT | prot;
  pt[(va >> PT_INDEX) & (MAX_ENTRIES - 1)] = pte;

  if (invlpg)
    __asm__ volatile("invlpg (%0)" ::"r"(va) : "memory");

  if (mapped_size)
    *mapped_size = PS_4K;

  return true;
}

bool pt::map_range(uintptr_t va, uintptr_t pa, size_t size, uintptr_t prot, bool invlpg,
                   uintptr_t va_clone_base, bool use_clone_size)
{
  return map_range_ex(AsmReadCr3(), va, pa, size, prot, invlpg, va_clone_base, use_clone_size);
}

bool pt::map_range_ex(uint64_t cr3, uintptr_t va, uintptr_t pa, size_t size, uintptr_t prot,
                      bool invlpg, uintptr_t va_clone_base, bool use_clone_size)
{
  size_t total_mapped;
  size_t page_size;
  uintptr_t current_va;
  uintptr_t current_pa;

  total_mapped = 0;
  current_va = va;
  current_pa = pa;
  while (total_mapped < size) {
    size_t remaining;
    size_t clone_page_size;
    uintptr_t current_prot;

    remaining = va + size - total_mapped;
    clone_page_size = 0;
    current_prot = prot;
    if (va_clone_base) {
      uintptr_t clone_va = va_clone_base + (current_va - va);
      uintptr_t flags = 0;
      if (pt::is_page_present_ex(cr3, clone_va, &clone_page_size, &flags))
        current_prot = flags;
    }

    if (use_clone_size && clone_page_size != 0) {
      if (clone_page_size == PS_1G && !(current_va & (PS_1G - 1)) && !(current_pa & (PS_1G - 1)))
        current_prot |= ENTRY_PS;
      else if (clone_page_size == PS_2M && !(current_va & (PS_2M - 1)) &&
               !(current_pa & (PS_2M - 1)))
        current_prot |= ENTRY_PS;
    }
    else {
      if (remaining >= PS_1G && !(current_va & (PS_1G - 1)) && !(current_pa & (PS_1G - 1)))
        current_prot |= ENTRY_PS;
      else if (remaining >= PS_2M && !(current_va & (PS_2M - 1)) && !(current_pa & (PS_2M - 1)))
        current_prot |= ENTRY_PS;
    }

    if (!mark_page_present_ex(cr3, current_va & ~(PS_4K - 1), current_pa & ~(PS_4K - 1),
                              current_prot, invlpg, &page_size))
      return false;

    total_mapped += page_size - (current_va & (PS_4K - 1));
    current_va += page_size;
    current_pa += page_size;
  }

  return true;
}

bool pt::is_range_mapped(uintptr_t address, size_t size)
{
  return is_range_mapped_ex(AsmReadCr3(), address, size);
}

bool pt::is_range_mapped_ex(uint64_t cr3, uintptr_t address, size_t size)
{
  size_t range_mapped;
  size_t page_size;

  range_mapped = 0;
  while (range_mapped < size) {
    if (!is_page_present(address, &page_size))
      return false;

    range_mapped += page_size;
  }

  return true;
}

size_t pt::mapped_range_from(uintptr_t address, uintptr_t *base)
{
  return mapped_range_from_ex(AsmReadCr3(), address, base);
}

size_t pt::mapped_range_from_ex(uint64_t cr3, uintptr_t address, uintptr_t *base)
{
  uintptr_t map_base;
  uintptr_t range_mapped;
  uintptr_t next;
  size_t page_size;

  range_mapped = 0;
  map_base = 0;
  next = address;
  while (is_page_present_ex(cr3, next, &page_size)) {
    if (!map_base) {
      map_base = address & ~(page_size - 1);
      next = map_base + page_size;
      if (base != nullptr) {
        range_mapped += page_size;
        *base = map_base;
      }
      else {
        range_mapped += page_size - (address & (page_size - 1));
      }

      continue;
    }

    next += page_size;
    range_mapped += page_size;
  }

  return range_mapped;
}

size_t pt::unmapped_range_from(uintptr_t address, uintptr_t *base)
{
  return unmapped_range_from_ex(AsmReadCr3(), address, base);
}

size_t pt::unmapped_range_from_ex(uint64_t cr3, uintptr_t address, uintptr_t *base)
{
  uintptr_t unmapped_base;
  uintptr_t range_unmapped;
  uintptr_t next;

  range_unmapped = 0;
  unmapped_base = 0;
  next = address;
  while (!is_page_present_ex(cr3, next)) {
    if (!unmapped_base) {
      unmapped_base = address & ~(EFI_PAGE_SIZE - 1);
      next = unmapped_base + EFI_PAGE_SIZE;
      if (base != nullptr) {
        range_unmapped += EFI_PAGE_SIZE;
        *base = unmapped_base;
      }
      else {
        range_unmapped += EFI_PAGE_SIZE - (address & (EFI_PAGE_SIZE - 1));
      }

      continue;
    }

    next += EFI_PAGE_SIZE;
    range_unmapped += EFI_PAGE_SIZE;
  }

  return range_unmapped;
}

size_t pt::frame_count(uintptr_t base, uintptr_t size, uint8_t level)
{
  uintptr_t pml5_frames;
  uintptr_t pml4_frames;
  uintptr_t pdpt_frames;
  uintptr_t pd_frames;
  uintptr_t pt_frames;
  bool la57;

  auto required_tables = [&](uintptr_t shift) -> uintptr_t {
    return ((base + size - 1) >> shift) - (base >> shift) + 1;
  };

  la57 = AsmReadCr4() & CR4_LA57;
  pml5_frames = (la57 && level >= 5) ? required_tables(PML5_INDEX) : 0;
  pml4_frames = (level >= 4) ? required_tables(PML4_INDEX) : 0;
  pdpt_frames = (level >= 3) ? required_tables(PDPT_INDEX) : 0;
  pd_frames = (level >= 2) ? required_tables(PD_INDEX) : 0;
  pt_frames = (level >= 1) ? required_tables(PT_INDEX) : 0;
  return pml5_frames + pml4_frames + pdpt_frames + pd_frames + pt_frames;
}

uintptr_t pt::new_frame()
{
  EFI_PHYSICAL_ADDRESS frame;

  if (g::state & POST_EXIT_BOOT_SERVICES) {
    if (g::state & KERNEL_MANAGED_FRAME_POOL_AVAILABLE)
      frame = kernel_managed_pool::get_next();
    else
      frame = reserved_pool::get_next();

    return frame;
  }

  else if (g::bs->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &frame) != EFI_SUCCESS)
    return 0;

  SetMem(reinterpret_cast<void *>(frame), EFI_PAGE_SIZE, 0);

  return frame;
}

uintptr_t pt::reserved_pool::get_next()
{
  uintptr_t next;
  if (reserved_used >= reserved_capacity || !reserved_frames) {
    dbg::serial_print("Failed to get next frame as there is none left\r\n");
    return 0;
  }

  next = reserved_frames + (reserved_used * EFI_PAGE_SIZE);
  reserved_used++;
  return next;
}

EFI_STATUS pt::reserved_pool::init_pool(size_t count)
{
  EFI_PHYSICAL_ADDRESS frames;
  EFI_STATUS status;
  size_t page_count;

  // UINT64_MAX / EFI_PAGE_SIZE would overflow
  if (count == UINT64_MAX / EFI_PAGE_SIZE)
    return EFI_INVALID_PARAMETER;

  page_count = count;
  status = g::bs->AllocatePages(AllocateAnyPages, EfiRuntimeServicesData, page_count, &frames);
  if (EFI_ERROR(status))
    return status;

  SetMem(reinterpret_cast<void *>(frames), page_count * EFI_PAGE_SIZE, 0);
  reserved_frames = frames;
  reserved_capacity = page_count;
  reserved_used = 1;

  return status;
}

uintptr_t pt::kernel_managed_pool::get_next()
{
  if (g::target_system == LINUX) {
    uintptr_t va;
    uintptr_t pa;

    if (linux_brk.brk_end == nullptr)
      return 0;

    va = *linux_brk.brk_end;
    if (va + PS_4K > linux_brk.brk_limit)
      return 0;

    pa = va - ::vmlinux::base + ::vmlinux::base_pa;
    if (pa == 0)
      return 0;

    SetMem(reinterpret_cast<void *>(va), PS_4K, 0);
    *linux_brk.brk_end += PS_4K;
    return pa;
  }

  return 0;
}

bool pt::kernel_managed_pool::init_pool(void *data)
{
  if (g::target_system == LINUX) {
    kernel_brk *brk;

    if (data == nullptr)
      return false;

    brk = reinterpret_cast<kernel_brk *>(data);

    if (!is_page_present(reinterpret_cast<uintptr_t>(brk->brk_end)))
      return false;

    linux_brk.brk_end = brk->brk_end;
    linux_brk.brk_limit = brk->brk_limit;
    return true;
  }

  return false;
}