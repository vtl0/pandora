#include <bootkit/binary/elf.hpp>

extern "C" {
#include <Library/BaseLib.h>
}

uintptr_t elf::get_export(void *addr, const char *sym)
{
  Elf64_Shdr *symtab;
  Elf64_Shdr *strtab;
  uintptr_t base;
  Elf64_Ehdr *ehdr;
  Elf64_Shdr *shdr;
  Elf64_Sym *symbols;
  const char *strings;
  Elf64_Xword sym_count;

  symtab = nullptr;
  strtab = nullptr;
  base = reinterpret_cast<uintptr_t>(addr);
  ehdr = reinterpret_cast<Elf64_Ehdr *>(addr);
  shdr = reinterpret_cast<Elf64_Shdr *>(base + ehdr->e_shoff);
  if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' || ehdr->e_ident[2] != 'L' ||
      ehdr->e_ident[3] != 'F')
    return 0;

  for (Elf64_Half i = 0; i < ehdr->e_shnum; i++) {
    if (shdr[i].sh_type == SHT_SYMTAB) {
      symtab = &shdr[i];
      strtab = &shdr[shdr[i].sh_link];
      break;
    }
  }

  if (symtab == nullptr || strtab == nullptr)
    return 0;

  symbols = reinterpret_cast<Elf64_Sym *>(base + symtab->sh_offset);
  strings = reinterpret_cast<const char *>(base + strtab->sh_offset);
  sym_count = symtab->sh_size / symtab->sh_entsize;
  for (Elf64_Xword i = 0; i < sym_count; i++) {
    Elf64_Sym *current_symbol = &symbols[i];

    if (current_symbol->st_name == 0)
      continue;

    if (ELF64_ST_BIND(current_symbol->st_info) != STB_GLOBAL ||
        ELF64_ST_TYPE(current_symbol->st_info) != STT_FUNC)
      continue;

    if (current_symbol->st_shndx == SHN_UNDEF)
      continue;

    if (AsciiStrCmp(strings + current_symbol->st_name, sym) == 0)
      return static_cast<uintptr_t>(current_symbol->st_value);
  }

  return 0;
}