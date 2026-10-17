#ifndef BZIMAGE_HOOKS_HPP_
#define BZIMAGE_HOOKS_HPP_

#include <bootkit/hooking/jmp_hooking.hpp>

#include <cstdint>

namespace hooks::bzimage {
  inline jmp_hook_ctx enter_kernel_hook_context;
  inline uintptr_t startup_64_addr;
  inline uint64_t startup_64_rsi;
  inline void *hook_stub;
  void *make_enter_kernel_hook_stub(uint8_t reg);
  void enter_kernel_hook();
  bool try_hook_enter_kernel(uintptr_t jmp_insn_address, uint8_t reg);
  bool do_hook_bzimage(uintptr_t bzimage_base, size_t size);
}

#endif // BZIMAGE_HOOKS_HPP_