#include <bootkit/arch/x86/memory.hpp>
#include <bootkit/binary/pe.hpp>

extern "C" {
#include <IndustryStandard/PeImage.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Uefi.h>
}

uintptr_t pe::get_export_address(const uintptr_t base, const char *name)
{
  EFI_IMAGE_DOS_HEADER *dos_hdr;
  EFI_IMAGE_NT_HEADERS64 *pe_header;
  EFI_IMAGE_EXPORT_DIRECTORY *export_dir;
  UINT32 *addresses;
  UINT32 *names;
  UINT16 *ordinals;
  UINT32 name_list_count;

  if (base == 0)
    return 0;

  dos_hdr = reinterpret_cast<EFI_IMAGE_DOS_HEADER *>(base);
  pe_header = reinterpret_cast<EFI_IMAGE_NT_HEADERS64 *>(base + dos_hdr->e_lfanew);
  export_dir = reinterpret_cast<EFI_IMAGE_EXPORT_DIRECTORY *>(
      base + pe_header->OptionalHeader.DataDirectory[0].VirtualAddress);
  addresses = reinterpret_cast<UINT32 *>(base + export_dir->AddressOfFunctions);
  names = reinterpret_cast<UINT32 *>(base + export_dir->AddressOfNames);
  ordinals = reinterpret_cast<UINT16 *>(base + export_dir->AddressOfNameOrdinals);
  name_list_count = export_dir->NumberOfNames;

  for (uint32_t i = 0; i < name_list_count; i++) {
    if (AsciiStrCmp(reinterpret_cast<char *>(base + names[i]), name) == 0) {
      return base + addresses[ordinals[i]];
    }
  }

  return 0;
}

uintptr_t pe::get_entry_point(const uintptr_t base)
{
  EFI_IMAGE_DOS_HEADER *dos_hdr;
  EFI_IMAGE_NT_HEADERS64 *pe_header;

  if (base == 0)
    return 0;

  dos_hdr = reinterpret_cast<EFI_IMAGE_DOS_HEADER *>(base);
  pe_header = reinterpret_cast<EFI_IMAGE_NT_HEADERS64 *>(base + dos_hdr->e_lfanew);

  return base + pe_header->OptionalHeader.AddressOfEntryPoint;
}

bool pe::get_section(uintptr_t base, const char *section_name, uintptr_t *section_base,
                     uintptr_t *section_size)
{
  EFI_IMAGE_DOS_HEADER *dos;
  EFI_IMAGE_NT_HEADERS64 *nt;
  EFI_IMAGE_SECTION_HEADER *sections;
  uintptr_t nt_address;
  uint16_t count;

  if (!base || !section_name)
    return false;

  dos = reinterpret_cast<EFI_IMAGE_DOS_HEADER *>(base);
  if (dos->e_magic != EFI_IMAGE_DOS_SIGNATURE)
    return false;

  nt = reinterpret_cast<EFI_IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
  if (nt->Signature != EFI_IMAGE_NT_SIGNATURE)
    return false;

  nt_address = reinterpret_cast<uintptr_t>(nt);
  sections = reinterpret_cast<EFI_IMAGE_SECTION_HEADER *>(nt_address + sizeof(nt->Signature) +
                                                          sizeof(EFI_IMAGE_FILE_HEADER) +
                                                          nt->FileHeader.SizeOfOptionalHeader);
  count = nt->FileHeader.NumberOfSections;

  for (uint16_t i = 0; i < count; i++) {
    EFI_IMAGE_SECTION_HEADER *current_section = &sections[i];
    char name[9];

    CopyMem(name, current_section->Name, 8);
    name[8] = '\0';

    if (AsciiStrCmp(section_name, name) == 0) {
      *section_base = base + current_section->VirtualAddress;
      *section_size = current_section->Misc.VirtualSize;
      return true;
    }
  }

  return false;
}

bool pe::get_code_section(uintptr_t base, uintptr_t *section_base, uintptr_t *section_size)
{
  EFI_IMAGE_DOS_HEADER *dos;
  EFI_IMAGE_NT_HEADERS64 *nt;
  EFI_IMAGE_SECTION_HEADER *sections;
  uintptr_t nt_address;
  uint16_t count;

  if (!base)
    return false;

  dos = reinterpret_cast<EFI_IMAGE_DOS_HEADER *>(base);
  if (dos->e_magic != EFI_IMAGE_DOS_SIGNATURE)
    return false;

  nt = reinterpret_cast<EFI_IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
  if (nt->Signature != EFI_IMAGE_NT_SIGNATURE)
    return false;

  nt_address = reinterpret_cast<uintptr_t>(nt);
  sections = reinterpret_cast<EFI_IMAGE_SECTION_HEADER *>(nt_address + sizeof(nt->Signature) +
                                                          sizeof(EFI_IMAGE_FILE_HEADER) +
                                                          nt->FileHeader.SizeOfOptionalHeader);
  count = nt->FileHeader.NumberOfSections;

  for (uint16_t i = 0; i < count; i++) {
    EFI_IMAGE_SECTION_HEADER *current_section = &sections[i];

    if ((current_section->Characteristics & EFI_IMAGE_SCN_CNT_CODE) ||
        (current_section->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE)) {
      *section_base = base + current_section->VirtualAddress;
      *section_size = current_section->Misc.VirtualSize;
      return true;
    }
  }

  return false;
}

// relocate PE image manually. reference:
// https://github.com/tianocore/edk2/blob/cc47dd45611737bda2cd9c6920e6a6b1bef6e4bb/MdePkg/Library/BasePeCoffLib/BasePeCoff.c#L957
bool pe::relocate(uintptr_t from, uintptr_t to, size_t size, uint64_t from_cr3)
{
  EFI_IMAGE_DOS_HEADER *dos_hdr;
  EFI_IMAGE_NT_HEADERS64 *nt_hdr;
  EFI_IMAGE_DATA_DIRECTORY *reloc_dir;
  uint8_t *current;
  uint8_t *end;
  int64_t delta;
  uint64_t saved_cr3;

  if (!from || !to || !size)
    return false;

  __asm__ volatile("mov %%cr3, %0\n\t"
                   "mov %1, %%cr3"
                   : "=&r"(saved_cr3)
                   : "r"(from_cr3)
                   : "memory");
  dos_hdr = reinterpret_cast<EFI_IMAGE_DOS_HEADER *>(from);
  nt_hdr = reinterpret_cast<EFI_IMAGE_NT_HEADERS64 *>(from + dos_hdr->e_lfanew);
  reloc_dir = &nt_hdr->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (!reloc_dir->Size) {
    __asm__ volatile("mov %0, %%cr3\n\t" ::"r"(saved_cr3) : "memory");
    return false;
  }

  current = reinterpret_cast<uint8_t *>(from + reloc_dir->VirtualAddress);
  delta = static_cast<int64_t>(to - from);
  end = current + reloc_dir->Size;
  while (current < end) {
    EFI_IMAGE_BASE_RELOCATION *reloc = reinterpret_cast<EFI_IMAGE_BASE_RELOCATION *>(current);
    uintptr_t target;
    size_t count;

    if (reloc->SizeOfBlock < sizeof(EFI_IMAGE_BASE_RELOCATION) ||
        current + reloc->SizeOfBlock > end)
      break;

    count = (reloc->SizeOfBlock - sizeof(EFI_IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
    for (size_t i = 0; i < count; i++) {
      uint16_t *entries;
      uint16_t entry;
      uint16_t type;

      entries = reinterpret_cast<uint16_t *>(&reloc[1]);
      entry = entries[i];
      type = entry >> 12;
      target = from + reloc->VirtualAddress + (entry & 0x0fff);
      if (target >= from && target + sizeof(uint64_t) <= from + size) {
        switch (type) {
        case EFI_IMAGE_REL_BASED_HIGHLOW:
          *reinterpret_cast<uint32_t *>(target) += static_cast<uint32_t>(delta);
          break;
        case EFI_IMAGE_REL_BASED_DIR64:
          *reinterpret_cast<uint64_t *>(target) += static_cast<uint64_t>(delta);
          break;
        default:
          break;
        }
      }
    }

    current += reloc->SizeOfBlock;
  }

  __asm__ volatile("mov %0, %%cr3\n\t" ::"r"(saved_cr3) : "memory");
  return true;
}

bool pe::fix_prot(uintptr_t va, bool keep_unnecessary_writable)
{
  static const char *unnecessary_sections[] = {
      ".reloc\0\0",
      ".pdata\0\0",
      ".debug\0\0",
      ".edata\0\0",
  };
  EFI_IMAGE_DOS_HEADER *dos_hdr;
  EFI_IMAGE_NT_HEADERS64 *nt_hdr;
  EFI_IMAGE_SECTION_HEADER *section;
  uintptr_t opt_hdr_addr;
  uint16_t section_count;
  uint16_t opt_hdr_size;

  dos_hdr = reinterpret_cast<EFI_IMAGE_DOS_HEADER *>(va);
  nt_hdr = reinterpret_cast<EFI_IMAGE_NT_HEADERS64 *>(va + dos_hdr->e_lfanew);
  opt_hdr_addr = reinterpret_cast<uintptr_t>(&nt_hdr->OptionalHeader);
  opt_hdr_size = nt_hdr->FileHeader.SizeOfOptionalHeader;
  section = reinterpret_cast<EFI_IMAGE_SECTION_HEADER *>(opt_hdr_addr + opt_hdr_size);
  section_count = nt_hdr->FileHeader.NumberOfSections;
  if (!pt::is_range_mapped(reinterpret_cast<uintptr_t>(section),
                           section_count * sizeof(EFI_IMAGE_SECTION_HEADER)))
    return false;

  for (uint16_t i = 0; i < section_count; i++) {
    uintptr_t section_va = va + section[i].VirtualAddress;
    uintptr_t prot = ENTRY_PRESENT;
    size_t page_size = 0;
    size_t protected_range = 0;

    if (section[i].Misc.VirtualSize == 0)
      continue;

    if (!(section[i].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE))
      prot |= ENTRY_NX;
    if (section[i].Characteristics & EFI_IMAGE_SCN_MEM_WRITE)
      prot |= ENTRY_RW;

    if (keep_unnecessary_writable) {
      for (size_t j = 0; j < ARRAY_SIZE(unnecessary_sections); j++) {
        if (CompareMem(unnecessary_sections[j], section[i].Name, sizeof(section[i].Name)) == 0)
          prot |= ENTRY_RW | ENTRY_NX;
      }
    }

    while (protected_range < ALIGN_VALUE(section[i].Misc.VirtualSize, PS_4K)) {
      if (!pt::set_page_prot(section_va + protected_range, prot, &page_size))
        return false;

      protected_range += page_size;
    }
  }

  return true;
}

bool pe::hide(uintptr_t va)
{
  static const char *unnecessary_sections[] = {
      ".reloc\0\0",
      ".pdata\0\0",
      ".debug\0\0",
      ".edata\0\0",
  };
  EFI_IMAGE_DOS_HEADER *dos_hdr;
  EFI_IMAGE_NT_HEADERS64 *nt_hdr;
  EFI_IMAGE_SECTION_HEADER *section;
  uintptr_t opt_hdr_addr;
  uint32_t size_of_headers;
  uint16_t section_count;
  uint16_t opt_hdr_size;

  dos_hdr = reinterpret_cast<EFI_IMAGE_DOS_HEADER *>(va);
  nt_hdr = reinterpret_cast<EFI_IMAGE_NT_HEADERS64 *>(va + dos_hdr->e_lfanew);
  opt_hdr_addr = reinterpret_cast<uintptr_t>(&nt_hdr->OptionalHeader);
  opt_hdr_size = nt_hdr->FileHeader.SizeOfOptionalHeader;
  section = reinterpret_cast<EFI_IMAGE_SECTION_HEADER *>(opt_hdr_addr + opt_hdr_size);
  size_of_headers = nt_hdr->OptionalHeader.SizeOfHeaders;
  section_count = nt_hdr->FileHeader.NumberOfSections;
  if (!pt::is_range_mapped(reinterpret_cast<uintptr_t>(section),
                           section_count * sizeof(EFI_IMAGE_SECTION_HEADER)))
    return false;

  for (uint16_t i = 0; i < section_count; i++) {
    uintptr_t section_va = va + section[i].VirtualAddress;

    if (section[i].Misc.VirtualSize == 0)
      continue;

    for (size_t j = 0; j < ARRAY_SIZE(unnecessary_sections); j++) {
      if (CompareMem(unnecessary_sections[j], section[i].Name, sizeof(section[i].Name)) != 0)
        continue;

      if (!pt::is_range_mapped(section_va, ALIGN_VALUE(section[i].Misc.VirtualSize, PS_4K)))
        continue;

      SetMem(reinterpret_cast<void *>(section_va), ALIGN_VALUE(section[i].Misc.VirtualSize, PS_4K),
             0);
      break;
    }
  }

  SetMem(reinterpret_cast<void *>(va), size_of_headers, 0);

  return true;
}