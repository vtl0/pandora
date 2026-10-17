#include <bootkit/arch/x86/memory.hpp>
#include <bootkit/binary/pe.hpp>
#include <bootkit/debug.hpp>
#include <bootkit/grub/grubx64.hpp>

extern "C" {
#include <Library/BaseLib.h>
}

bool grubx64::init_grub_internals(uintptr_t grub_module_base, size_t module_length)
{
  // I have never seen a GRUB 2 build with .rodata, just in case if its used in the
  // future
  pe::get_section(grub_module_base, ".rodata", &grubx64::rodata_section_address,
                  &grubx64::rodata_section_size);
  if (!pe::get_section(grub_module_base, ".data", &grubx64::data_section_address,
                       &grubx64::data_section_size)) {
    dbg::print(DEBUG_ERROR, "Couldn't find GRUB .data section\r\n");
    return false;
  }
  if (!pe::get_code_section(grub_module_base, &grubx64::text_section_address,
                            &grubx64::text_section_size)) {
    dbg::print(DEBUG_ERROR, "Couldn't find GRUB code section\r\n");
    return false;
  }

  return true;
}

bool grubx64::find_symtab()
{
  // GRUB 2 generates a custom symtab which we can parse to resolve symbols to addresses.
  // the structure definition is consistent in every GRUB 2.X version
  // https://elixir.bootlin.com/grub/2.00/source/grub-core/gensymlist.sh#L52
  uint8_t *c;
  symtab *candidate;
  uintptr_t data_end, text_end;

  if (!grubx64::data_section_address || !grubx64::data_section_size || !grubx64::text_section_address ||
      !grubx64::text_section_size)
    return false;

  data_end = (grubx64::data_section_address + grubx64::data_section_size);
  text_end = (grubx64::text_section_address + grubx64::text_section_size);
  c = reinterpret_cast<uint8_t *>(grubx64::data_section_address);
  candidate = nullptr;
  // GRUB builtin symtab is in alphabetical order, grub_abort is a safe pick
  // grub_abort is usually the first entry, but we'll walk backwards so no
  // entries are left out
  for (size_t i = 0; i < grubx64::data_section_size - sizeof("grub_abort"); i++) {
    // first find string literal, then find XREF to it
    if (AsciiStrCmp("grub_abort", reinterpret_cast<const CHAR8 *>(&c[i])) == 0) {
      uintptr_t xref = 0;
      bool found = false;

      // look for the xref
      for (size_t j = 0; j < grubx64::data_section_size - sizeof(uintptr_t); j += sizeof(uintptr_t)) {
        if (*reinterpret_cast<uint8_t **>(&c[j]) == &c[i]) {
          uintptr_t symbol_addr;

          xref = reinterpret_cast<uintptr_t>(&c[j]);
          candidate = reinterpret_cast<symtab *>(xref);
          // grub_abort is a function
          if (!candidate->isfunc) {
            candidate = nullptr;
            continue;
          }

          symbol_addr = reinterpret_cast<uintptr_t>(candidate->addr);
          // check if symbol is within GRUB's .text
          if (symbol_addr < grubx64::text_section_address || symbol_addr >= text_end) {
            candidate = nullptr;
            continue;
          }

          found = true;
          break;
        }
      }

      if (found) {
        break;
      }
    }
  }

  if (candidate == nullptr)
    return false;

  symtab_count = 1;
  // walk backwards to the first symtab entry
  do {
    symtab *entry;
    uintptr_t entry_address;
    uintptr_t symbol_address;
    uintptr_t name_address;

    entry = &candidate[-1];
    entry_address = reinterpret_cast<uintptr_t>(entry);
    if (entry_address < grubx64::data_section_address)
      break;

    if (!entry->name || !entry->addr)
      break;

    symbol_address = reinterpret_cast<uintptr_t>(entry->addr);
    if (entry->isfunc &&
        (symbol_address < grubx64::text_section_address || symbol_address >= text_end))
      break;

    name_address = reinterpret_cast<uintptr_t>(entry->name);
    if (!pt::is_page_present(name_address) || !pt::is_page_present(symbol_address))
      break;

    symtab_count++;
    candidate = &candidate[-1];
  } while (true);

  // count valid entries forward
  do {
    symtab *entry;
    uintptr_t entry_address;
    uintptr_t symbol_address;
    uintptr_t name_address;

    entry = &candidate[symtab_count];
    entry_address = reinterpret_cast<uintptr_t>(entry);
    if (entry_address >= data_end - sizeof(symtab))
      break;

    if (!entry->name || !entry->addr)
      break;

    symbol_address = reinterpret_cast<uintptr_t>(entry->addr);
    if (entry->isfunc &&
        (symbol_address < grubx64::text_section_address || symbol_address >= text_end))
      break;

    name_address = reinterpret_cast<uintptr_t>(entry->name);
    if (!pt::is_page_present(name_address) || !pt::is_page_present(symbol_address))
      break;

    symtab_count++;
  } while (true);

  symtab_array = candidate;
  return true;
}

uintptr_t grubx64::find_symbol(const char *name)
{
  uintptr_t addr = 0;

  for (size_t i = 0; i < symtab_count; i++) {
    if (AsciiStrCmp(name, symtab_array[i].name) == 0) {
      addr = reinterpret_cast<uintptr_t>(symtab_array[i].addr);
      break;
    }
  }

  return addr;
}