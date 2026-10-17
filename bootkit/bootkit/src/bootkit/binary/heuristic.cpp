#include <bootkit/arch/x86/memory.hpp>
#include <bootkit/binary/heuristic.hpp>
#include <bootkit/binary/pe.hpp>
#include <bootkit/general.hpp>
#include <bootkit/linux/kallsyms.hpp>
#include <bootkit/linux/vmlinux.hpp>

extern "C" {
#include <IndustryStandard/PeImage.h>
#include <Library/BaseMemoryLib.h>
}

static int memcmp(const void *str1, const void *str2, size_t count)
{
  const unsigned char *s1 = (const unsigned char *)str1;
  const unsigned char *s2 = (const unsigned char *)str2;

  while (count-- > 0) {
    if (*s1++ != *s2++)
      return s1[-1] < s2[-1] ? -1 : 1;
  }
  return 0;
}

uintptr_t heuristic::retroactive_find_pe_base(uintptr_t addr)
{
  uintptr_t base = 0;
  uintptr_t page = addr & ~EFI_PAGE_MASK;
  for (; pt::is_page_present(page); page -= EFI_PAGE_SIZE) {
    EFI_IMAGE_DOS_HEADER *dos_hdr = reinterpret_cast<EFI_IMAGE_DOS_HEADER *>(page);
    if (dos_hdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
      EFI_IMAGE_NT_HEADERS64 *nt_hdr =
          reinterpret_cast<EFI_IMAGE_NT_HEADERS64 *>(page + dos_hdr->e_lfanew);
      if (page + dos_hdr->e_lfanew > addr)
        continue;

      if (nt_hdr->Signature == EFI_IMAGE_NT_SIGNATURE) {
        base = page;
        break;
      }
    }
  }
  return base;
}

uintptr_t heuristic::get_event_signal_queue()
{
  // consistent .data structure across versions. XREF'ed by
  // CoreCreateEventInternal, present in DxeCore image
  // github.com/tianocore/edk2/blob/6a6ec8a228b6dd99f9a52a78c2a4c82be9b73ec8/MdeModulePkg/Core/Dxe/Event/Event.c#L42
  // github.com/tianocore/edk2/blob/6a6ec8a228b6dd99f9a52a78c2a4c82be9b73ec8/MdeModulePkg/Core/Dxe/Event/Event.c#L387
  static const UINT32 event_table[] = {
      EVT_TIMER | EVT_NOTIFY_SIGNAL,
      EVT_TIMER,
      EVT_NOTIFY_WAIT,
      EVT_NOTIFY_SIGNAL,
      EVT_SIGNAL_EXIT_BOOT_SERVICES,
      EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE,
      0x00000000,
      EVT_TIMER | EVT_NOTIFY_WAIT,
  };
  // XREF'ed by same function, CoreCreateEventInternal
  // github.com/tianocore/edk2/blob/6a6ec8a228b6dd99f9a52a78c2a4c82be9b73ec8/MdeModulePkg/Core/Dxe/Event/Event.c#L37
  // github.com/tianocore/edk2/blob/6a6ec8a228b6dd99f9a52a78c2a4c82be9b73ec8/MdeModulePkg/Core/Dxe/Event/Event.c#L504
  uintptr_t dxe_core_ptr;
  uintptr_t dxe_core_data;
  size_t dxe_core_data_size;
  uintptr_t dxe_core_code;
  size_t dxe_core_code_size;
  uintptr_t structure_location;
  uintptr_t function_point;
  size_t remaining_size;
  uint8_t *c;
  bool found_bt;

  // CreateEvent is also in DxeCore
  dxe_core_ptr = reinterpret_cast<uintptr_t>(g::bs->CreateEvent);
  dxe_core_ptr = retroactive_find_pe_base(dxe_core_ptr);
  if (!dxe_core_ptr)
    return 0;

  if (!pe::get_section(dxe_core_ptr, ".data", &dxe_core_data, &dxe_core_data_size))
    return 0;

  if (dxe_core_data_size < 4096)
    return 0;

  structure_location = 0;
  c = reinterpret_cast<uint8_t *>(dxe_core_data);
  for (uintptr_t i = 0; i < dxe_core_data_size - sizeof(event_table); i++) {
    // Standard compilation flags for EDK2 optimize aggressively for size. My
    // assumption: the compiler kept the structure in .data and referenced it
    // in CoreCreateEventInternal. Worth noting that it is never written to,
    // even though it is writable. It is uniquely read by aforementioned
    // function and is effectively constant, allowing for constant propagation.
    if (CompareMem(&c[i], event_table, sizeof(event_table)) == 0) {
      structure_location = dxe_core_data + i;
      break;
    }
  }

  if (!pe::get_code_section(dxe_core_ptr, &dxe_core_code, &dxe_core_code_size))
    return 0;
  if (dxe_core_code_size < 4096)
    return 0;

  function_point = 0;
  c = reinterpret_cast<uint8_t *>(dxe_core_code);
  // Fallback logic.
  if (!structure_location) {
    size_t last_index = 0;
    int cond_bitmask = 0;
    uint8_t last_reg = 0xFF;
    for (size_t i = 1; i < dxe_core_code_size - 64; i++) {
      uint32_t imm32;
      uint8_t current_rex;
      uint8_t current_modrm;
      uint8_t current_mod;
      uint8_t current_rm;
      uint8_t current_reg;
      bool current_has_rex;

      if (c[i] != 0x81 /* CMP */)
        continue;

      current_has_rex = P_IS_REX(c[i - 1]);
      current_rex = c[i - 1];
      // must be 32 bit
      if (current_has_rex && (current_rex & P_W_BIT))
        continue;

      current_modrm = c[i + 1];
      current_mod = current_modrm >> 6;
      current_rm = current_modrm & 0b111;
      current_reg = (current_modrm >> 3) & 0b111;
      // cmp reg
      if (current_mod != 0b11)
        continue;
      // not a cmp
      if (current_reg != 0b111)
        continue;
      if (current_has_rex && !(current_rex & P_B_BIT)) {
        // ESP and EBP are nonsensical here
        if (current_rm == 4 || current_rm == 5)
          continue;
      }

      imm32 = *reinterpret_cast<uint32_t *>(&c[i + 2]);
      if (i - last_index > 24)
        cond_bitmask = 0;
      if (last_reg != 0xFF && (last_reg != current_rm)) {
        last_reg = current_rm;
        cond_bitmask = 0;
      }

      if (imm32 == EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE)
        cond_bitmask |= 0b01;
      else if (imm32 == EVT_SIGNAL_EXIT_BOOT_SERVICES)
        cond_bitmask |= 0b10;
      else
        continue;

      last_index = i;
      last_reg = current_rm;
      if (cond_bitmask == 0b11) {
        function_point = dxe_core_code + i + 6;
        break;
      }
    }
  }
  else {
    for (size_t i = 0; i < dxe_core_code_size - 64; i++) {
      uintptr_t destination;
      uint8_t current_rex;
      uint8_t current_modrm;
      uint8_t current_mod;
      uint8_t current_rm;
      uint8_t current_reg;

      if (c[i + 1] != 0x8d /* LEA */)
        continue;

      if (!P_IS_REX(c[i]))
        continue;

      current_rex = c[i];
      if (!(current_rex & P_W_BIT))
        continue;

      current_modrm = c[i + 2];
      current_mod = current_modrm >> 6;
      current_rm = current_modrm & 0b111;

      // not rip relative
      if (current_mod != 0 || current_rm != 0b101)
        continue;

      current_reg = (current_modrm >> 3) & 0b111;
      // RSP and RBP are nonsensical here
      if ((current_reg == 4 || current_reg == 5) && !(current_rex & P_R_BIT))
        continue;

      destination = dxe_core_code + i + 7 + *reinterpret_cast<int32_t *>(&c[i + 3]);
      if (destination == structure_location) {
        function_point = dxe_core_code + i + 7;
        break;
      }
    }
  }

  if (!function_point) {
    return 0;
  }

  found_bt = false;
  remaining_size = dxe_core_code_size - (function_point - dxe_core_code);
  c = reinterpret_cast<uint8_t *>(function_point);
  for (size_t i = 0; i < remaining_size - 64; i++) {
    uint8_t current_rex;
    uint8_t current_modrm;
    uint8_t current_mod;
    uint8_t current_rm;
    uint8_t current_reg;

    if (found_bt) {
      if (c[i + 1] != 0x8d /* LEA */)
        continue;

      if (!P_IS_REX(c[i]))
        continue;

      current_rex = c[i];
      if (!(current_rex & P_W_BIT))
        continue;

      current_modrm = c[i + 2];
      current_mod = current_modrm >> 6;
      current_rm = current_modrm & 0b111;

      // not rip relative
      if (current_mod != 0 || current_rm != 0b101)
        continue;

      current_reg = (current_modrm >> 3) & 0b111;
      // EFIAPI in x86_64 -> Microsoft x64
      // ListHead RCX
      // InsertHeadList (LIST_ENTRY  *ListHead, LIST_ENTRY  *Entry);
      if (current_reg != 1 && !(current_rex & P_R_BIT))
        continue;

      return function_point + i + 7 + *reinterpret_cast<int32_t *>(&c[i + 3]);
    }
    else {
      // has to be 32 bit reg
      if (P_IS_REX(c[i]) && (c[i] & P_W_BIT))
        continue;

      // not bt
      if (c[i] != 0x0F || c[i + 1] != 0xBA)
        continue;

      current_modrm = c[i + 2];
      current_mod = current_modrm >> 6;
      current_reg = (current_modrm >> 3) & 0b111;
      current_rm = current_modrm & 0b111;
      // not bt reg
      if (current_mod != 0b11)
        continue;

      // not bt
      if (current_reg != 0b100)
        continue;

      // not & 200h
      if (c[i + 3] != 9)
        continue;

      found_bt = true;
    }
  }

  return 0;
}

bool heuristic::is_enter_kernel(uintptr_t c, uint8_t *what_reg)
{
  uint8_t *code = reinterpret_cast<uint8_t *>(c);
  int pos;
  uint8_t modrm, mod, rm;
  uint8_t rex;
  uint8_t reg;
  uint8_t dst;
  bool req_mov_rsi;

  // https://elixir.bootlin.com/linux/v6.19.8/source/drivers/firmware/efi/libstub/x86-stub.c#L898
  // all bzImages I could find inlines this function as it is static and tiny. Note [2026/08/14]:
  // couldn't be otherwise. While refactoring this code, I came to the conclusion static __noreturn
  // will always cause this to be inlined. Needed to clearify this in the public release.
  // asm("jmp *%0"::"r"(kernel_addr), "S"(boot_params)); guarantees it assigns
  // RSI right before the jmp
  if (*code != 0xFF /* jmp reg */)
    return false;

  pos = 0;
  rex = 0;
  modrm = code[1];
  mod = modrm >> 6;
  rm = modrm & 0b111;
  reg = (modrm >> 3) & 0b111;
  if (reg != 4) // not a JMP
    return false;
  if (mod != 3) // not JMP reg
    return false;

  dst = rm;
  if (P_IS_REX(code[-1])) {
    rex = code[-1];
  }
  // cannot be a jmp rsi
  if (!(rex & P_B_BIT) && dst == 6)
    return false;

  // first check old fixed predictable signature
  // https://elixir.bootlin.com/linux/v6.0/source/arch/x86/boot/compressed/head_64.S#L560
  if (code[1] == 0xE0 /* rax */) {
    // mov rsi, rbx; lea rax, [rax + X]
    if (memcmp(&code[-10], "\x48\x89\xDE\x48\x8D\x80", 6) == 0) {
      // and rsp, 0FFFFFFFFFFFFFFF0h; mov rbx, rdx; call efi_main
      if (memcmp(&code[-22], "\x48\x83\xE4\xF0\x48\x89\xD3\xE8", 8) == 0) {
        *what_reg = dst | ((rex & P_B_BIT) ? 0b1000 : 0);
        return true;
      }
    }
  }

  req_mov_rsi = false;
  pos -= 3 + (rex ? 1 : 0);
  while (pos > -15) {
    uint8_t current_dst = 255;
    uint8_t current_reg, current_modrm, current_mod, current_rm;
    uint8_t current_rex = 0;
    bool is_rsi = false;
    bool is_same_reg = false;

    // modrm movs, 0xb8 to 0xbf and 0xc7 make no sense here
    if (code[pos + 1] == 0x89 || code[pos + 1] == 0x8b) {
      if (!P_IS_REX(code[pos]))
        break;

      current_rex = code[pos];
      if (!(current_rex & P_W_BIT))
        break;

      current_modrm = code[pos + 2];
      current_mod = current_modrm >> 6;
      current_rm = current_modrm & 0b111;
      current_reg = (current_modrm >> 3) & 0b111;

      switch (code[pos + 1]) {
      case 0x89:
        if (current_mod == 3) {
          current_dst = current_rm;
          is_rsi = (current_dst == 6) && !(current_rex & P_B_BIT);
          is_same_reg = (current_dst == dst) && ((current_rex & P_B_BIT) == (rex & P_B_BIT));
        }
        break;
      case 0x8B:
        current_dst = current_reg;
        is_rsi = (current_dst == 6) && !(current_rex & P_R_BIT);
        is_same_reg = (current_dst == dst) && ((current_rex & P_R_BIT) == (rex & P_B_BIT));
        break;
      }

      if (is_rsi)
        req_mov_rsi = true;
      else if (!is_same_reg)
        break;
    }
    // add to reg destination
    // the reason I check for an add instruction is that kernel_entry in enter_kernel(kernel_entry,
    // ...); is written as *kernel_entry = addr + entry; in the static function
    // efi_decompress_kernel. Therefore the compiler can optimize and move this addition to right
    // before enter_kernel(), which is the first usage of kernel_entry written by
    // efi_decompress_kernel. compilers are surprisingly smart.
    else if (code[pos + 1] == 0x03 || code[pos + 1] == 0x01 || code[pos] == 0x03 ||
             code[pos - 1] == 0x03 || code[pos - 2] == 0x03 || code[pos - 3] == 0x03) {
      int expected = 3;

      if (code[pos + 1] != 0x01) {
        if (code[pos] == 0x03) {
          expected = 4;
          pos -= 1;
        }
        else if (code[pos - 1] == 0x03) {
          expected = 5;
          pos -= 2;
        }
        else if (code[pos - 2] == 0x03) {
          expected = 6;
          pos -= 3;
        }
        else if (code[pos - 3] == 0x03) {
          expected = 7;
          pos -= 4;
        }
      }

      current_rex = code[pos];
      if (!P_IS_REX(current_rex) || !(current_rex & P_W_BIT))
        break;

      current_modrm = code[pos + 2];
      current_mod = current_modrm >> 6;
      current_rm = current_modrm & 0b111;
      current_reg = (current_modrm >> 3) & 0b111;

      if (code[pos + 1] == 0x01) {
        if ((rex & P_B_BIT) != (current_rex & P_B_BIT) || mod != 3)
          break;
        if (current_rm != dst)
          break;
      }
      else if (code[pos + 1] == 0x03) {
        int actual = 3;
        if ((rex & P_B_BIT) != (current_rex & P_R_BIT))
          break;
        if (current_reg != dst)
          break;

        // if SIB
        actual += (current_rm == 4 && current_mod != 3) ? 1 : 0;
        switch (current_mod) {
        case 0:
          if (current_rm == 5)
            actual += 4;
          break;
        case 1:
          actual += 1;
          break;
        case 2:
          actual += 4;
          break;
        }

        if (actual != expected)
          break;
      }
    }
    pos -= 3;
  }

  if (!req_mov_rsi)
    return false;

  // blind searching for this heuristic often finds 2 matches, we need the one jumping to
  // startup_64. before enter_kernel(kernel_entry, boot_params), bzImage calls sev_enable
  // and efi_5level_switch. Therefore, two E8 call instructions has to be 5 bytes apart
  // and precede the enter_kernel inline
  // https://elixir.bootlin.com/linux/v7.1.8/source/drivers/firmware/efi/libstub/x86-stub.c#L1040
  for (int i = 5; i < 32; i++) {
    if (code[-i] == 0xE8 /* efi_5level_switch() */ && code[-i - 5] == 0xE8 /* sev_enable() */) {
      *what_reg = dst | ((rex & P_B_BIT) ? 0b1000 : 0);
      return true;
    }
  }

  return false;
}

// https://elixir.bootlin.com/linux/v6.19.8/source/arch/x86/kernel/head_64.S#L140
// some old versions do: mov cr3, rax; .*; movq $1f, %rax; jmp *%rax
uintptr_t heuristic::find_startup_64_va_jmp(uintptr_t code, uintptr_t *mov_cr3_address,
                                            bool *is_old_pattern)
{
  uint8_t *pos = reinterpret_cast<uint8_t *>(code);
  uintptr_t mov_address;
  bool mov_cr3_found = false;

  if (code == 0 || mov_cr3_address == nullptr || is_old_pattern == nullptr)
    return 0;

  for (int i = 0; i < 512; pos++, i++) {
    // mov cr3, rax
    if (memcmp(pos, "\x0F\x22\xD8", 3) == 0) {
      mov_address = reinterpret_cast<uintptr_t>(pos);
      mov_cr3_found = true;
      break;
    }
  }
  if (mov_cr3_found) {
    for (int i = 0; i < 32; pos++, i++) {
      if (memcmp(pos, "\xFF\x25", 2) == 0) {
        *is_old_pattern = false;
        *mov_cr3_address = mov_address;
        return reinterpret_cast<uintptr_t>(pos);
      }
      // old pattern
      if (memcmp(pos, "\x48\xB8", 2) == 0 && memcmp(&pos[10], "\xFF\xE0", 2) == 0) {
        *is_old_pattern = true;
        *mov_cr3_address = mov_address;
        return reinterpret_cast<uintptr_t>(&pos[10]);
      }
    }
  }

  return 0;
}

// pages should be contiguous
uintptr_t heuristic::retroactive_find_elf_base(uintptr_t code)
{
  uintptr_t base = 0;
  uintptr_t page = code & ~(EFI_PAGE_SIZE - 1);
  for (; page; page -= EFI_PAGE_SIZE) {
    if (CompareMem(reinterpret_cast<void *>(page),
                   "\x7f"
                   "ELF",
                   4) == 0) {
      base = page;
      break;
    }
  }
  return base;
}

uintptr_t heuristic::retroactive_find_map_base(uintptr_t va)
{
  uintptr_t previous_page;
  uintptr_t addr;
  size_t page_size;
  size_t previous_page_size;

  if (!pt::is_page_present(va, &page_size))
    return 0;

  addr = va & ~(page_size - 1);
  while (addr >= page_size) {
    previous_page = addr - 1;
    if (!pt::is_page_present(previous_page, &previous_page_size))
      break;

    if (previous_page_size > page_size)
      break;

    page_size = previous_page_size;
    addr = previous_page & ~(page_size - 1);
  }

  return addr;
}

uintptr_t heuristic::bruteforce_find_vmlinux_base(uintptr_t base, uintptr_t limit)
{
  uintptr_t candidate;
  size_t step;
  bool found = false;

  if (limit - base < PS_2M)
    step = PS_2M;
  else
    step = PS_4K;

  candidate = base;
  found = false;
  for (candidate = base; candidate < limit; candidate += step) {
    if (pt::is_page_present(candidate)) {
      found = true;
      break;
    }
  }

  if (!found)
    return 0;

  return heuristic::retroactive_find_map_base(candidate);
}

uintptr_t heuristic::forward_find_map_end(uintptr_t va)
{
  uintptr_t addr;
  size_t page_size;

  if (!pt::is_page_present(va, &page_size))
    return 0;

  addr = (va & ~(page_size - 1)) + page_size;
  while (true) {
    if (!pt::is_page_present(addr, &page_size))
      break;

    addr += page_size;
  }

  return addr;
}

uintptr_t heuristic::find_next_map_with_prot(uintptr_t va, uintptr_t desired_prot)
{
  uintptr_t addr;
  uintptr_t page_flags;
  size_t page_size;

  if (!pt::is_page_present(va, &page_size, &page_flags))
    return 0;

  if ((page_flags & PT_PROT_MASK) == desired_prot)
    return va & ~(page_size - 1);

  addr = va & ~(page_size - 1);
  while (true) {
    addr += page_size;
    if (!pt::is_page_present(addr, &page_size, &page_flags))
      return 0;

    if ((page_flags & PT_PROT_MASK) == desired_prot)
      break;
  }

  return addr;
}

uintptr_t heuristic::find_init_mem_mapping_cr3_mov(uintptr_t init_mem_mapping,
                                                   uintptr_t early_memtest, uint8_t *what_reg)
{
  uint8_t *c = reinterpret_cast<uint8_t *>(init_mem_mapping);
  uintptr_t call_early_memtest_addr;
  size_t max_search_size;

  // kallsyms parsing could be broken, and init_mem_mapping is in init memory which can
  // be freed, check if its in present memory
  if (!init_mem_mapping || !pt::is_page_present(init_mem_mapping))
    return 0;

  // 2048 is very conservative, 1000 is often enough to find the cr3 writing point
  max_search_size = 2048;
  if (!pt::is_page_present(init_mem_mapping + max_search_size)) {
    max_search_size = 1024;
    if (!pt::is_page_present(init_mem_mapping + max_search_size))
      return 0;
  }

  call_early_memtest_addr = 0;
  for (size_t i = 0; i < max_search_size - 5; i++) {
    // jmp or call, last function called is early_memtest. it can be either an JMP to
    // early_memtest or a call + ret. both init_mem_mapping and early_memtest are void,
    // so this is usually optimized to an E9 jmp
    // https://elixir.bootlin.com/linux/v7.2.2/source/arch/x86/mm/init.c#L812
    if (c[i] == 0xE8 || c[i] == 0xE9) {
      int32_t disp = *reinterpret_cast<int32_t *>(&c[i + 1]);
      if (init_mem_mapping + i + 5 + disp == early_memtest) {
        call_early_memtest_addr = reinterpret_cast<uintptr_t>(&c[i]);
        break;
      }
    }
  }

  if (!call_early_memtest_addr)
    return 0;

  // now walk backwards and find FF 15 ?? ?? ?? ?? E8 for CONFIG_PARAVIRT kernels or
  // mov cr3, reg; E8 ?? ?? ?? ?? otherwise
  c = reinterpret_cast<uint8_t *>(call_early_memtest_addr);
  for (size_t i = 8; i < call_early_memtest_addr - init_mem_mapping; i++) {
    // CONFIG_PARAVIRT makes so load_cr3 is called from a function pointer in a structure
    // called pv_mmu_ops (load_cr3 inlines to write_cr3). __flush_tlb_all is called right
    // after, and its never inlined
    // https://elixir.bootlin.com/linux/v7.1.8/source/arch/x86/include/asm/paravirt_types.h#L122
    if (c[-i] == 0xFF && c[-i + 1] == 0x15 && c[-i + 6] == 0xE8) {
      uint8_t *wcr3_c;
      uintptr_t __flush_tlb_all;
      uintptr_t ff_15_rip;
      uintptr_t ff_15_call_dst;
      int32_t ff_25_disp32;
      int32_t disp32;

      disp32 = *reinterpret_cast<int32_t *>(&c[-i + 7]);
      __flush_tlb_all = reinterpret_cast<uintptr_t>(&c[-i + 6]) + 5 + disp32;
      if (!pt::is_page_present(__flush_tlb_all))
        continue;

      ff_15_rip = reinterpret_cast<uintptr_t>(&c[-i]) + 6;
      ff_25_disp32 = *reinterpret_cast<int32_t *>(&c[-i + 2]);
      if (!pt::is_page_present(ff_15_rip + ff_25_disp32))
        continue;

      ff_15_call_dst = *reinterpret_cast<uintptr_t *>(ff_15_rip + ff_25_disp32);
      if (!pt::is_page_present(ff_15_call_dst))
        continue;

      wcr3_c = reinterpret_cast<uint8_t *>(ff_15_call_dst);
      for (size_t j = 0; j < 128; j++) {
        if (wcr3_c[j] == 0x0F && wcr3_c[j + 1] == 0x22) {
          uint8_t modrm, mod, rm, reg;
          bool rex_b_bit;

          if (j && P_IS_REX(wcr3_c[j - 1]) && (wcr3_c[j - 1] & P_B_BIT))
            rex_b_bit = true;
          else
            rex_b_bit = false;

          modrm = wcr3_c[j + 2];
          mod = modrm >> 6;
          if (mod != 0b11)
            continue;

          reg = (modrm >> 3) & 0b111;
          if (reg != 0b11)
            continue;

          rm = modrm & 0b111;
          *what_reg = rm | (rex_b_bit ? 0b1000 : 0);
          if (j && P_IS_REX(wcr3_c[j - 1]))
            return reinterpret_cast<uintptr_t>(&wcr3_c[j - 1]);

          return reinterpret_cast<uintptr_t>(&wcr3_c[j]);
        }
      }
    }

    // mov cr3, reg; E8 to __flush_tlb_all
    if (c[-i] == 0x0F && c[-i + 1] == 0x22 && c[-i + 3] == 0xE8) {
      uintptr_t __flush_tlb_all;
      int32_t disp32;

      disp32 = *reinterpret_cast<int32_t *>(&c[-i + 4]);
      __flush_tlb_all = reinterpret_cast<uintptr_t>(&c[-i + 3]) + 5 + disp32;
      if (!pt::is_page_present(__flush_tlb_all)) {
        uint8_t modrm, mod, rm, reg;
        bool rex_b_bit;

        if (P_IS_REX(c[-i - 1]) && (c[-i - 1] & P_B_BIT))
          rex_b_bit = true;
        else
          rex_b_bit = false;

        modrm = c[-i + 2];
        mod = modrm >> 6;
        if (mod != 0b11)
          continue;

        reg = (modrm >> 3) & 0b111;
        if (reg != 0b11)
          continue;

        rm = modrm & 0b111;
        *what_reg = rm | (rex_b_bit ? 0b1000 : 0);
        if (P_IS_REX(c[-i - 1]))
          return reinterpret_cast<uintptr_t>(&c[-i - 1]);

        return reinterpret_cast<uintptr_t>(&c[-i]);
      }
    }
  }

  return 0;
}

uintptr_t heuristic::find_set_pmd_used_by_cleanup_highmap(uintptr_t cleanup_highmap)
{
  uint8_t *c = reinterpret_cast<uint8_t *>(cleanup_highmap);
  uintptr_t max;

  if (!cleanup_highmap || !kallsyms::kallsyms_available())
    return 0;

  max = MIN(pt::mapped_range_from(cleanup_highmap), 256);
  for (uintptr_t i = 0; i < max; i++) {
    if (c[i] == 0xE8) {
      uintptr_t set_pmd;
      uintptr_t destination;
      int32_t disp32;

      disp32 = *reinterpret_cast<int32_t *>(&c[i + 1]);
      destination = cleanup_highmap + i + 5 + disp32;
      if (!pt::is_page_present(destination))
        continue;

      set_pmd = 0;
      kallsyms::for_each([&](const char *name, uintptr_t addr, char type) -> bool {
        if (type != 'T' && type != 't' && type != 'W' && type != 'w')
          return false;

        if (addr != destination || !AsciiStrStr(name, "set_pmd"))
          return false;

        set_pmd = addr;
        return true;
      });

      if (set_pmd)
        return set_pmd;
    }
  }

  return 0;
}

bool heuristic::shim_find_system_services_hook_functions(uintptr_t shim_base, size_t shim_size,
                                                         uintptr_t *hook, uintptr_t *unhook)
{
  static constexpr auto loadimage_offset = offsetof(EFI_BOOT_SERVICES, LoadImage);
  static constexpr auto unloadimage_offset = offsetof(EFI_BOOT_SERVICES, UnloadImage);
  static constexpr auto startimage_offset = offsetof(EFI_BOOT_SERVICES, StartImage);
  uint8_t *c = reinterpret_cast<uint8_t *>(shim_base);
  uintptr_t shim_init_str;
  uintptr_t shim_init_point;
  uintptr_t destination;
  uintptr_t code_section;
  size_t code_size;
  int32_t disp32;
  uint8_t mask;
  bool hook_found;
  bool unhook_found;
  bool is_writing;

  auto is_accessing_disp = [&](uint8_t *code, int32_t offset, bool is_disp32) -> bool {
    int32_t disp;
    uint8_t rex;
    uint8_t modrm;
    uint8_t mod;
    uint8_t rm;
    uint8_t sib;
    bool assume_sib = false;

    if (offset != 0) {
      if (is_disp32) {
        disp = *reinterpret_cast<int32_t *>(code);
        if (disp != offset)
          return false;
      }
      else {
        disp = *reinterpret_cast<int8_t *>(code);
        if (disp != static_cast<int8_t>(offset))
          return false;
      }
    }

    // 8B for reads, 89 for writes
    if (code[-3] == 0x8B || code[-3] == 0x89) {
      assume_sib = true;
    }
    else if (code[-2] != 0x8B && code[-2] != 0x89)
      return false;

    rex = code[assume_sib ? -4 : -3];
    if (!P_IS_REX(rex))
      return false;
    if (!(rex & P_W_BIT) || (rex & P_X_BIT))
      return false;

    modrm = code[assume_sib ? -2 : -1];
    mod = modrm >> 6;
    rm = modrm & 0b111;
    // rm says it has SIB
    if (rm == 4) {
      // nonsensical
      if (!assume_sib)
        return false;
      // not RSP relative
      if (rex & P_B_BIT)
        return false;
    }

    // reg to reg, not what we want
    if (mod == 0b11)
      return false;
    // mismatch, mod 1 implies disp8 (and disp32 when 2)
    if (mod == 0b01 && is_disp32)
      return false;
    if (mod == 0b10 && !is_disp32)
      return false;
    // displacement 0 or rip relative
    if (mod == 0b00 && ((offset != 0) || rm == 5))
      return false;

    if (assume_sib) {
      sib = code[-1];
      // fixed offset
      if ((sib & 0b111000) != 0b100000)
        return false;
    }

    if (code[assume_sib ? -3 : -2] == 0x89)
      is_writing = true;
    else
      is_writing = false;

    return true;
  };

  if (!shim_base || shim_size < 4096 || !hook || !unhook)
    return false;

  // "shim_init" string is solely referenced by shim_init function, by finding a XREF to
  // it we have a point to search from inside shim_init
  shim_init_str = 0;
  for (size_t i = 0; i < shim_size - 10; i++) {
    if (memcmp(&c[i], "shim_init", 10) == 0) {
      shim_init_str = shim_base + i;
      break;
    }
  }

  // alternatively, try "set_second_stage() failed: %r\n", same case as aforementioned string
  if (!shim_init_str) {
    for (size_t i = 0; i < shim_size - 31; i++) {
      if (memcmp(&c[i], "set_second_stage() failed: %r\n", 31) == 0) {
        shim_init_str = shim_base + i;
        break;
      }
    }
  }

  if (!shim_init_str)
    return false;

  if (pe::get_code_section(shim_base, &code_section, &code_size)) {
    c = reinterpret_cast<uint8_t *>(code_section);
  }
  else {
    code_section = shim_base;
    code_size = shim_size;
  }

  // find the XREF to either strings
  shim_init_point = 0;
  for (size_t i = 0; i < code_size - 6; i++) {
    destination = code_section + i + 4 + *reinterpret_cast<int32_t *>(&c[i]);
    if (destination == shim_init_str) {
      if (!pt::is_page_present(destination))
        continue;

      // typically impossible, just in case
      if (pt::mapped_range_from(code_section + i + 4) < 384)
        continue;

      shim_init_point = code_section + i + 4;
      break;
    }
  }

  if (!shim_init_point)
    return false;

  hook_found = false;
  unhook_found = false;
  c = reinterpret_cast<uint8_t *>(shim_init_point);
  // this size could be lucky enough so call unhook_system_table is within search scope, but
  // we will recheck it later and look for another search range. shim_init and shim_fini is
  // usually adjacent
  for (int i = 0; i < 384 - sizeof(int32_t); i++) {
    if (hook_found && unhook_found)
      break;

    // E8 call
    if (c[i] != 0xE8)
      continue;

    disp32 = *reinterpret_cast<int32_t *>(&c[i + 1]);
    destination = shim_init_point + i + 5 + disp32;
    // ensure it is within .text
    if (destination < code_section || destination >= code_section + code_size)
      continue;

    if (pt::mapped_range_from(destination) < 128)
      continue;

    // bitmask logic: bit 0, 1 and 2 are for LoadImage, UnloadImage and StartImage
    // respectively. for each one that is also read from the original table, it is
    // or'ed shifting left by 3, so bit 3, 4, 5 signals they're being read & saved,
    // coherent with a hooking logic which preserves old pointers to unhook later
    mask = 0;
    for (int j = 4; j < 128 - 8; j++) {
      uint8_t *f = reinterpret_cast<uint8_t *>(destination);
      is_writing = false;

      // looks like the end of the function? weakest heuristic yet, would checking
      // other valid E8 calls to deduce function boundaries be worth the effort?
      // 128 is hardly ever sufficient to cover both functions even when adjacent.
      // in Debian signed shimx64, both functions are roughly 96-100 bytes each. we
      // iterate over 128 bytes so the search size itself makes this more reliable.
      if (f[j] == 0xC3) {
        // endbr64
        if (memcmp(&f[j + 1], "\xF3\x0F\x1E\xFA", 4) == 0)
          break;

        // last thing unhook_system_services does is an assignment, hook_system_services too.
        // could be lea + mov or mov to global var. cover both by checking if last 4 bytes look
        // like a valid disp32 or a mov [reg], some_other_reg
        // https://github.com/rhboot/shim/blob/4dc4a1bf85542706d345230eb72a0e52d6f0c452/loader-proto.c#L36
        // https://github.com/rhboot/shim/blob/4dc4a1bf85542706d345230eb72a0e52d6f0c452/loader-proto.c#L502
        if (j >= sizeof(int32_t)) {
          uintptr_t destination2;
          disp32 = *reinterpret_cast<int32_t *>(&f[-4]);
          destination2 = destination + j + disp32;
          if (destination2 >= shim_base && destination2 < shim_base + shim_size)
            break;

          if (P_IS_REX(f[j - 3]) && !(f[j - 3] & P_X_BIT)) {
            if (f[j - 2] == 0x89) {
              uint8_t modrm = f[j - 1];
              uint8_t mod = modrm >> 6;
              uint8_t rm = modrm & 0b111;

              // [reg], no offset or rip relative
              if (mod == 0b00 && rm != 5)
                break;
            }
          }
        }
      }

      // precedence of uint32_t check over uint8_t as the order could give false
      // matches in the 2 different variations we verify (sorry for the ugly code)
      if (is_accessing_disp(&f[j], static_cast<int32_t>(loadimage_offset), true)) {
        mask |= 0b001 << (is_writing ? 3 : 0);
      }
      else if (is_accessing_disp(&f[j], static_cast<int8_t>(loadimage_offset), false)) {
        mask |= 0b001 << (is_writing ? 3 : 0);
      }
      else if (is_accessing_disp(&f[j], static_cast<int32_t>(unloadimage_offset), true)) {
        mask |= 0b010 << (is_writing ? 3 : 0);
      }
      else if (is_accessing_disp(&f[j], static_cast<int8_t>(unloadimage_offset), false)) {
        mask |= 0b010 << (is_writing ? 3 : 0);
      }
      else if (is_accessing_disp(&f[j], static_cast<int32_t>(startimage_offset), true)) {
        mask |= 0b100 << (is_writing ? 3 : 0);
      }
      else if (is_accessing_disp(&f[j], static_cast<int8_t>(startimage_offset), false)) {
        mask |= 0b100 << (is_writing ? 3 : 0);
      }
    }

    // writes to all 3
    if (mask & 0b111000) {
      // btw, unhook also accesses offsetof(EFI_BOOT_SERVICES, Exit), but this could
      // be moved out to another unhook function in the future, would make sense so
      // don't account for it here.

      // reads from all 3, means it is saving them
      if (mask & 0b111) {
        hook_found = true;
        *hook = destination;
      }
      else {
        unhook_found = true;
        *unhook = destination;
      }
    }
  }

  // unhook function is not called from within shim_init and no neighboring caller in
  // the search range (typically shim_fini) was found. try finding efi_main, walk forward,
  // locate shim_fini (the call following init_grub), and finally unhook_system_services
  if (!unhook_found && hook_found) {
    uintptr_t efi_main_point = 0;
    uintptr_t shim_fini = 0;
    size_t search_range;
    bool init_grub_found;

    c = reinterpret_cast<uint8_t *>(code_section);
    if (code_size < 7)
      return false;

    // find a point close to the end of efi_main
    for (size_t i = 0; i < code_size - 7; i++) {
      // REX with W bit + LEA
      if (!P_IS_REX(c[i]) || !(c[i] & P_W_BIT) || c[i + 1] != 0x8D)
        continue;

      disp32 = *reinterpret_cast<int32_t *>(&c[i + 3]);
      destination = code_section + i + 7 + disp32;
      if (destination < shim_base || destination > ((shim_base + shim_size) - 38) || (destination & 1))
        continue;

      // we'll walk forward from lea reg, L"ShimRetainProtocol" in efi_main
      if (!StrCmp(L"ShimRetainProtocol"_uefi, reinterpret_cast<const CHAR16 *>(destination))) {
        efi_main_point = code_section + i + 7;
        break;
      }
    }

    if (!efi_main_point)
      return false;

    c = reinterpret_cast<uint8_t *>(efi_main_point);
    search_range = (code_section + code_size) - efi_main_point;
    if (search_range < 5)
      return false;

    // find call to shim_fini
    init_grub_found = false;
    for (size_t i = 0; i < search_range - 5; i++) {
      // call
      if (c[i] != 0xE8)
        continue;

      disp32 = *reinterpret_cast<int32_t *>(&c[i + 1]);
      destination = efi_main_point + i + 5 + disp32;
      if (destination < code_section || destination >= code_section + code_size)
        continue;

      if (init_grub_found) {
        shim_fini = destination;
        break;
      }

      if ((code_section + code_size) - destination < 832)
        continue;

      // identify init_grub, next call is shim_fini. inside init_grub, should_use_fallback
      // (static) is very likely to be inlined. if so, the lea reg, "start_image() returned %r\n"
      // identification wont ever realistically hit and we use the inlined should_use_fallback
      // signature instead. start_image shouldn't inline, lets pray it doesn't
      for (size_t j = 0; j < 832; j++) {
        uint8_t *f = reinterpret_cast<uint8_t *>(destination);
        uintptr_t destination2;

        // REX with W bit + LEA
        if (!P_IS_REX(f[j]) || !(f[j] & P_W_BIT) || f[j + 1] != 0x8D)
          continue;

        disp32 = *reinterpret_cast<int32_t *>(&f[j + 3]);
        destination2 = destination + j + 7 + disp32;
        if (destination2 < shim_base || destination2 > (shim_base + shim_size) - 20)
          continue;

        // still in range for a realistic inlined should_use_fallback. perror expands a string
        // containing the function name, test for it
        if (j < 160 &&
            !AsciiStrCmp("should_use_fallback", reinterpret_cast<CHAR8 *>(destination2))) {
          init_grub_found = true;
          i += 4; // 4, since i++ will make it 5 to skip this E8 ?? ?? ?? ??
          break;
        }
        if (!AsciiStrCmp("start_image() returned %r\n", reinterpret_cast<CHAR8 *>(destination2))) {
          init_grub_found = true;
          i += 4; // 4, since i++ will make it 5 to skip this E8 ?? ?? ?? ??
          break;
        }
      }
    }

    if (!shim_fini)
      return false;

    if ((code_section + code_size) - shim_fini < 128)
      return false;

    c = reinterpret_cast<uint8_t *>(shim_fini);
    for (int i = 0; i < 128 - 5; i++) {
      // call
      if (c[i] != 0xE8)
        continue;

      disp32 = *reinterpret_cast<int32_t *>(&c[i + 1]);
      destination = shim_fini + i + 5 + disp32;
      if (destination < code_section || destination >= code_section + code_size)
        continue;

      if ((code_section + code_size) - destination < 128)
        continue;

      mask = 0;
      for (int j = 4; j < 128 - 8; j++) {
        uint8_t *f = reinterpret_cast<uint8_t *>(destination);
        is_writing = false;

        // function end detection
        if (j >= sizeof(int32_t)) {
          uintptr_t destination2;
          disp32 = *reinterpret_cast<int32_t *>(&f[-4]);
          destination2 = destination + j + disp32;
          if (destination2 >= shim_base && destination2 < shim_base + shim_size)
            break;

          if (P_IS_REX(f[j - 3]) && !(f[j - 3] & P_X_BIT)) {
            if (f[j - 2] == 0x89) {
              uint8_t modrm = f[j - 1];
              uint8_t mod = modrm >> 6;
              uint8_t rm = modrm & 0b111;

              // [reg], no offset or rip relative
              if (mod == 0b00 && rm != 5)
                break;
            }
          }
        }

        if (is_accessing_disp(&f[j], static_cast<int32_t>(loadimage_offset), true)) {
          mask |= 0b001 << (is_writing ? 3 : 0);
        }
        else if (is_accessing_disp(&f[j], static_cast<int8_t>(loadimage_offset), false)) {
          mask |= 0b001 << (is_writing ? 3 : 0);
        }
        else if (is_accessing_disp(&f[j], static_cast<int32_t>(unloadimage_offset), true)) {
          mask |= 0b010 << (is_writing ? 3 : 0);
        }
        else if (is_accessing_disp(&f[j], static_cast<int8_t>(unloadimage_offset), false)) {
          mask |= 0b010 << (is_writing ? 3 : 0);
        }
        else if (is_accessing_disp(&f[j], static_cast<int32_t>(startimage_offset), true)) {
          mask |= 0b100 << (is_writing ? 3 : 0);
        }
        else if (is_accessing_disp(&f[j], static_cast<int8_t>(startimage_offset), false)) {
          mask |= 0b100 << (is_writing ? 3 : 0);
        }
      }

      // writes to all 3
      if (mask & 0b111000) {
        // unhook DOES NOT read from all 3
        if ((mask & 0b111) != 0b111) {
          unhook_found = true;
          *unhook = destination;
        }
      }

      if (unhook_found)
        break;
    }
  }

  return hook_found && unhook_found;
}

bool heuristic::is_valid_ascii_string(const char *s, size_t *size)
{
  size_t len = 0;

  if (s == nullptr)
    return false;

  for (; *s; s++, len++) {
    if (*s < ' ' || *s > '~')
      return false;
  }

  if (size)
    *size = len;

  return true;
}

bool heuristic::is_valid_kallsyms(uintptr_t num_syms_addr, kallsyms::ks *ksms)
{
  using namespace kallsyms;
  unsigned int num_syms;

  // get_symbol_seq assumes maximum of 3 bytes for the size, minimum is
  // quite arbitrary to be completely honest (if you have data to suggest
  // a change, tell me)
  // https://elixir.bootlin.com/linux/v7.1.8/source/kernel/kallsyms.c#L165
  num_syms = *reinterpret_cast<unsigned int *>(num_syms_addr);
  if (num_syms < 128 || num_syms > 0xFFFFFF /* UINT24_MAX*/)
    return false;

  if (is_valid_kallsyms_ex(num_syms_addr, ksms, 4)) {
    ksms->traits |= TRAIT_ALIGN_4_BYTES;
    return true;
  }

  if (is_valid_kallsyms_ex(num_syms_addr, ksms, 8)) {
    ksms->traits |= TRAIT_ALIGN_8_BYTES;
    return true;
  }

  return false;
}

bool heuristic::is_valid_kallsyms_ex(uintptr_t num_syms_addr, kallsyms::ks *ksms, int alignment)
{
  using namespace kallsyms;
  ks found_ksms = {};
  unsigned int *p_num_syms;
  uint8_t *names;
  uint32_t *markers;
  const char *token_table;
  uint16_t *token_index;
  size_t names_size;
  size_t markers_size;
  unsigned int num_syms;
  unsigned int markers_count;
  uint32_t inferred_traits;
  uint16_t token_table_size;
  bool is_uleb;

  p_num_syms = reinterpret_cast<unsigned int *>(num_syms_addr);
  num_syms = *p_num_syms;
  names = reinterpret_cast<uint8_t *>(ALIGN_VALUE(num_syms_addr + sizeof(unsigned int), alignment));
  names_size = get_kallsyms_names_size(names, num_syms, &is_uleb);
  if (names_size == 0)
    return false;

  markers_count = (num_syms + 255) / 256;
  markers = reinterpret_cast<uint32_t *>(
      ALIGN_VALUE(reinterpret_cast<uintptr_t>(names) + names_size, alignment));
  if (!is_kallsyms_markers_valid(markers, markers_count))
    return false;

  markers_size = markers_count * sizeof(uint32_t);
  token_table = reinterpret_cast<const char *>(
      ALIGN_VALUE(reinterpret_cast<uintptr_t>(markers) + markers_size, alignment));
  token_table_size = get_kallsyms_token_table_size(token_table);
  if (token_table_size == 0)
    return false;

  token_index = reinterpret_cast<uint16_t *>(
      ALIGN_VALUE(reinterpret_cast<uintptr_t>(token_table) + token_table_size, alignment));
  if (!is_kallsyms_token_index_valid(token_index, token_table_size))
    return false;

  found_ksms.num_syms = num_syms;
  found_ksms.names = names;
  found_ksms.markers = markers;
  found_ksms.token_table = token_table;
  found_ksms.token_index = token_index;
  found_ksms.traits = is_uleb ? TRAIT_NAME_LEN_ULEB128 : TRAIT_NAME_LEN_U8;

  inferred_traits = 0;
  if (heuristic::kallsyms_are_offsets_post_token_index(&found_ksms, &inferred_traits, alignment)) {
    found_ksms.traits |= inferred_traits | TRAIT_OFFSETS_POST_TOKEN_INDEX;
    *ksms = found_ksms;
    return true;
  }

  inferred_traits = 0;
  if (heuristic::kallsyms_are_offsets_before_num_syms(&found_ksms, num_syms_addr)) {
    found_ksms.traits |= inferred_traits | TRAIT_OFFSETS_PRECEDES_NUM_SYMS;
    *ksms = found_ksms;
    return true;
  }

  return false;
}

bool heuristic::is_valid_kallsyms_offsets(int32_t *syms, unsigned int count, uint32_t traits,
                                          uintptr_t kallsyms_relative_base)
{
  using namespace kallsyms;
  uintptr_t prev;

  if (syms == nullptr || count == 0)
    return false;

  prev = syms[0];

  if (traits & TRAIT_ADDR_ABSOLUTE) {
    uintptr_t *syms_abs = reinterpret_cast<uintptr_t *>(syms);
    prev = syms_abs[0];

    for (unsigned int i = 0; i < count; i++) {
      if (syms_abs[i] < prev)
        return false;

      prev = syms_abs[i];
    }

    return true;
  }

  for (unsigned int i = 0; i < count; i++) {
    if (traits & TRAIT_ADDR_SELF_DISPLACED) {
      uintptr_t addr = reinterpret_cast<uintptr_t>(&syms[i]) + syms[i];

      if (i == 0)
        prev = addr;

      if (addr < prev)
        return false;

      prev = addr;
    }
    else if (traits & TRAIT_ADDR_BASE_DISPLACED) {
      if (traits & TRAIT_ADDR_ABSOLUTE_PERCPU) {
        // https://elixir.bootlin.com/linux/v6.9.7/source/kernel/kallsyms.c#L159
        // https://elixir.bootlin.com/linux/v6.9.7/source/kernel/kallsyms.c#L163
        uint64_t addr = syms[i] >= 0 ? syms[i] : kallsyms_relative_base - 1 - syms[i];

        if (i == 0)
          prev = syms[0] >= 0 ? syms[0] : kallsyms_relative_base - 1 - syms[0];

        if (addr < prev)
          return false;

        prev = addr;
      }
      else {
        // cast them to u32
        // https://elixir.bootlin.com/linux/v6.9.7/source/kernel/kallsyms.c#L156
        // https://elixir.bootlin.com/linux/v6.9.7/source/scripts/kallsyms.c#L504
        uint32_t addr = syms[i];

        if (addr < prev)
          return false;

        prev = addr;
      }
    }
    else {
      if (syms[i] < prev)
        return false;

      prev = syms[i];
    }
  }

  return true;
}

bool heuristic::is_kallsyms_markers_valid(uint32_t *markers, unsigned int count)
{
  uintptr_t markers_addr = reinterpret_cast<uintptr_t>(markers);
  size_t markers_size = static_cast<size_t>(count) * sizeof(uint32_t);

  if (markers == nullptr || !pt::is_range_mapped(markers_addr, markers_size))
    return false;

  for (unsigned int i = 1; i < count; i++) {
    if (markers[i] <= markers[i - 1])
      return false;
  }

  return true;
}

bool heuristic::is_kallsyms_token_index_valid(uint16_t *token_index, uint16_t token_table_size)
{
  if (token_index == nullptr || !pt::is_range_mapped(reinterpret_cast<uintptr_t>(token_index), 512))
    return false;

  if (token_index[0] != 0)
    return false;

  for (int i = 1; i < 256; i++) {
    if (token_index[i] <= token_index[i - 1] || token_index[i] >= token_table_size)
      return false;
  }

  return true;
}

bool heuristic::kallsyms_are_offsets_before_num_syms(kallsyms::ks *lo, uintptr_t num_syms_addr)
{
  using namespace kallsyms;
  uintptr_t kallsyms_relative_base;
  uintptr_t offsets_address;
  size_t offsets_size;
  int32_t *offs;

  // tests for TRAIT_ADDR_BASE_DISPLACED kallsyms
  if (pt::is_page_present(num_syms_addr - 8)) {
    kallsyms_relative_base = *reinterpret_cast<uint64_t *>(num_syms_addr - 8);
    if (kallsyms_relative_base >= X86_64_KERNEL_VA_MIN &&
        kallsyms_relative_base <= X86_64_KERNEL_VA_MAX) {
      offsets_size = static_cast<size_t>(lo->num_syms) * sizeof(int32_t);
      // has to be 8 byte aligned as per the architecture
      offsets_address = num_syms_addr - 8 - offsets_size - (!IS_ALIGNED(offsets_size, 8) ? 4 : 0);
      offs = reinterpret_cast<int32_t *>(offsets_address);
      if (pt::is_range_mapped(offsets_address, offsets_size)) {
        // if CONFIG_KALLSYMS_ABSOLUTE_PERCPU is not set, offsets are unsigned integers
        if (heuristic::is_valid_kallsyms_offsets(offs, lo->num_syms, TRAIT_ADDR_BASE_DISPLACED)) {
          lo->offsets = offs;
          lo->kallsyms_relative_base = kallsyms_relative_base;
          lo->traits |= TRAIT_ADDR_BASE_DISPLACED;
          return true;
        }

        // if CONFIG_KALLSYMS_ABSOLUTE_PERCPU IS set
        if (heuristic::is_valid_kallsyms_offsets(
                offs, lo->num_syms, TRAIT_ADDR_BASE_DISPLACED | TRAIT_ADDR_ABSOLUTE_PERCPU,
                kallsyms_relative_base)) {
          lo->offsets = offs;
          lo->kallsyms_relative_base = kallsyms_relative_base;
          lo->traits |= TRAIT_ADDR_BASE_DISPLACED | TRAIT_ADDR_ABSOLUTE_PERCPU;
          return true;
        }
      }
    }
  }

  // test for TRAIT_ADDR_ABSOLUTE
  offsets_size = static_cast<size_t>(lo->num_syms) * sizeof(uint64_t);
  offsets_address = num_syms_addr - offsets_size;
  if (!IS_ALIGNED(offsets_address, 8))
    return false;

  offs = reinterpret_cast<int32_t *>(offsets_address);
  if (!pt::is_range_mapped(offsets_address, offsets_size))
    return false;

  // is_valid_kallsyms_offsets casts offs to <uintptr_t *> when TRAIT_ADDR_ABSOLUTE
  if (!heuristic::is_valid_kallsyms_offsets(offs, lo->num_syms, TRAIT_ADDR_ABSOLUTE))
    return false;

  lo->addresses = reinterpret_cast<uintptr_t *>(offs);
  lo->kallsyms_relative_base = 0;
  lo->traits |= TRAIT_ADDR_ABSOLUTE;

  return true;
}

bool heuristic::kallsyms_are_offsets_post_token_index(kallsyms::ks *lo, uint32_t *traits,
                                                      int alignment)
{
  using namespace kallsyms;
  uintptr_t offsets_address;
  uintptr_t offsets_end;
  size_t offsets_size;
  uintptr_t kallsyms_relative_base;
  int32_t *offsets;

  // token index has size 256 * sizeof(uint16_t) (512)
  offsets_address = ALIGN_VALUE(reinterpret_cast<uintptr_t>(lo->token_index) + 512, alignment);
  offsets_size = static_cast<size_t>(lo->num_syms) * sizeof(int32_t);
  if (!pt::is_range_mapped(offsets_address, offsets_size))
    return false;

  offsets = reinterpret_cast<int32_t *>(offsets_address);
  offsets_end = offsets_address + offsets_size;
  // tests for TRAIT_ADDR_BASE_DISPLACED kallsyms
  if (pt::is_page_present(ALIGN_VALUE(offsets_end, 8))) {
    kallsyms_relative_base = *reinterpret_cast<uintptr_t *>(ALIGN_VALUE(offsets_end, 8));
    if (kallsyms_relative_base >= X86_64_KERNEL_VA_MIN &&
        kallsyms_relative_base <= X86_64_KERNEL_VA_MAX) {
      if (heuristic::is_valid_kallsyms_offsets(offsets, lo->num_syms, TRAIT_ADDR_BASE_DISPLACED,
                                               kallsyms_relative_base)) {
        lo->offsets = offsets;
        lo->kallsyms_relative_base = kallsyms_relative_base;
        *traits = TRAIT_ADDR_BASE_DISPLACED;
        return true;
      }

      if (heuristic::is_valid_kallsyms_offsets(
              offsets, lo->num_syms, TRAIT_ADDR_BASE_DISPLACED | TRAIT_ADDR_ABSOLUTE_PERCPU,
              kallsyms_relative_base)) {
        lo->offsets = offsets;
        lo->kallsyms_relative_base = kallsyms_relative_base;
        *traits = TRAIT_ADDR_BASE_DISPLACED | TRAIT_ADDR_ABSOLUTE_PERCPU;
        return true;
      }
    }
  }

  if (!heuristic::is_valid_kallsyms_offsets(offsets, lo->num_syms, TRAIT_ADDR_SELF_DISPLACED))
    return false;

  lo->offsets = offsets;
  lo->kallsyms_relative_base = 0;
  *traits = TRAIT_ADDR_SELF_DISPLACED;
  return true;
}

size_t heuristic::get_kallsyms_names_size(uint8_t *names, unsigned int num_syms, bool *uleb128)
{
  uint8_t *c;
  uintptr_t names_address;
  uintptr_t map_end;
  size_t pos;
  size_t page_size;
  bool is_uleb;

  names_address = reinterpret_cast<uintptr_t>(names);
  if (!pt::is_page_present(names_address, &page_size))
    return 0;

  c = names;
  pos = 0;
  is_uleb = false;
  map_end = (names_address & ~(page_size - 1)) + page_size;
  for (unsigned int i = 0; i < num_syms; i++) {
    uintptr_t addr;
    uint32_t length;

    addr = reinterpret_cast<uintptr_t>(&c[pos]);
    if (addr + 2 > map_end) {
      if (!pt::is_page_present(addr, &page_size))
        return 0;

      map_end = (addr & ~(page_size - 1u)) + page_size;
    }

    if (c[pos] == 0)
      return 0;

    // old name limit was 128, but the check did >= 128, so its actually
    // 127 (literally 0b01111111), just the MSB not set. if set, its the
    // new ULEB128 length convention. very convenient for the heuristic
    // https://elixir.bootlin.com/linux/v6.9.7/source/scripts/kallsyms.c#L155
    // https://elixir.bootlin.com/linux/v6.9.7/source/scripts/kallsyms.c#L444
    if (c[pos] & 0b10000000) {
      length = c[pos] & 0b01111111;
      length |= static_cast<uint32_t>(c[pos + 1]) << 7;
      is_uleb = true;
      pos += 1;
    }
    else
      length = c[pos];

    pos += 1;
    // linux kernel limits kallsyms name length to 0x3FFF for ULEB128
    // https://elixir.bootlin.com/linux/v6.9.7/source/scripts/kallsyms.c#L432
    if (length > 0x3FFF)
      return 0;

    addr = reinterpret_cast<uintptr_t>(&c[pos + length]);
    while (map_end <= addr) {
      if (!pt::is_page_present(map_end, &page_size))
        return 0;

      map_end += page_size;
    }

    pos += length;
  }

  *uleb128 = is_uleb;
  return pos;
}

uint16_t heuristic::get_kallsyms_token_table_size(const char *token_table)
{
  unsigned int strings_count = 0;
  uint16_t pos = 0;

  while (strings_count < 256) {
    size_t len;

    if (!is_valid_ascii_string(&token_table[pos], &len))
      return 0;

    // len 0 is invalid for token table
    if (len == 0 || len >= UINT16_MAX - pos)
      return 0;

    pos += static_cast<uint16_t>(len + 1 /* '\0' */);
    strings_count++;
  }

  return pos;
}

template<size_t N>
struct image_signature {
  char str[N]{};
  size_t len{0};

  template<size_t LEN>
  constexpr image_signature(const char (&s)[LEN]) : len(LEN - 1)
  {
    static_assert(LEN <= N, "Signature bigger than buffer size");
    for (size_t i = 0; i < LEN - 1; ++i) {
      str[i] = s[i];
    }
  }
};

template<size_t N, size_t FIXED_MAX>
constexpr size_t max_sig_len(const image_signature<FIXED_MAX> (&arr)[N])
{
  size_t max_len = 0;
  for (size_t i = 0; i < N; ++i) {
    if (arr[i].len > max_len)
      max_len = arr[i].len;
  }
  return max_len;
}

bool heuristic::is_grub(uintptr_t image_base, size_t image_size)
{
  static constexpr image_signature<64> signatures[] = {"grub_mod_init", "grub_mod_fini",
                                                       "grub_dl_load_core_noinit", "grub rescue>"};
  static constexpr size_t max_len = max_sig_len(signatures);

  if (image_size >= max_len) {
    size_t search_limit = image_size - max_len;
    uintptr_t mods_base, mods_size;
    for (uintptr_t i = 0; i <= search_limit; i++) {
      const char *c = reinterpret_cast<const char *>(image_base + i);
      for (const auto &s : signatures) {
        if (memcmp(c, s.str, s.len) == 0)
          return true;
      }
    }

    if (pe::get_section(image_base, "mods", &mods_base, &mods_size)) {
      if (mods_base + 4 < image_base + image_size) {
        void *mods_sig_p = reinterpret_cast<void *>(mods_base);
        return memcmp(mods_sig_p, "mimg", 4) == 0;
      }
    }
  }

  return false;
}

bool heuristic::is_uki(uintptr_t image_base, size_t image_size)
{
  uintptr_t contained_bzimage_base, contained_bzimage_size;
  if (pe::get_section(image_base, ".linux", &contained_bzimage_base, &contained_bzimage_size))
    return true;

  return false;
}

bool heuristic::is_systemd_stub(uintptr_t image_base, size_t image_size)
{
  static constexpr image_signature<64> signatures[] = {
      "systemd/src/boot/stub.c", "systemd.stub.kernel-cmdline-extra", "systemd-stub"};
  static constexpr size_t max_str_len = max_sig_len(signatures);

  if (image_size >= max_str_len) {
    size_t search_limit = image_size - max_str_len;
    for (uintptr_t i = 0; i <= search_limit; i++) {
      const char *c = reinterpret_cast<const char *>(image_base + i);
      for (const auto &s : signatures) {
        if (memcmp(c, s.str, s.len) == 0)
          return true;
      }
    }
  }

  return false;
}

bool heuristic::is_systemd_boot(uintptr_t image_base, size_t image_size)
{
  return false;
}

bool heuristic::is_bootmgfw(uintptr_t image_base, size_t image_size)
{
  static constexpr image_signature<64> signatures[] = {"bootmgfw.pdb"};
  static constexpr size_t max_str_len = max_sig_len(signatures);

  if (image_size >= max_str_len) {
    size_t search_limit = image_size - max_str_len;
    for (uintptr_t i = 0; i <= search_limit; i++) {
      const char *c = reinterpret_cast<const char *>(image_base + i);
      for (const auto &s : signatures) {
        if (memcmp(c, s.str, s.len) == 0)
          return true;
      }
    }
  }

  return false;
}

bool heuristic::is_winload(uintptr_t image_base, size_t image_size)
{
  return false;
}

bool heuristic::is_bzimage(uintptr_t image_base, size_t image_size)
{
  uint8_t *c;

  if (image_size < 0x206)
    return false;

  c = reinterpret_cast<uint8_t *>(image_base);
  if (memcmp(&c[0x202], "HdrS", 4) != 0)
    return false;

  return true;
}

bool heuristic::is_veracrypt(uintptr_t image_base, size_t image_size)
{
  return false;
}

bool heuristic::is_shimx64(uintptr_t image_base, size_t image_size)
{
  static constexpr image_signature<64> signatures[] = {"github.com/rhboot/shim", "UEFI SHIM\n"};
  static constexpr size_t max_str_len = max_sig_len(signatures);
  uintptr_t dummy_base;
  size_t dummy_size;

  if (image_size >= max_str_len) {
    size_t search_limit = image_size - max_str_len;
    for (uintptr_t i = 0; i <= search_limit; i++) {
      const char *c = reinterpret_cast<const char *>(image_base + i);
      for (const auto &s : signatures) {
        if (memcmp(c, s.str, s.len) == 0)
          return true;
      }
    }
  }

  if (pe::get_section(image_base, ".sbatlevel", &dummy_base, &dummy_size))
    return true;

  return false;
}
