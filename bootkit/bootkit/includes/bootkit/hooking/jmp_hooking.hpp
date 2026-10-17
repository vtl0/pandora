#ifndef JMP_HOOKING_HPP
#define JMP_HOOKING_HPP

#include <cstdint>

typedef struct {
  uintptr_t from;
  uint32_t checksum;
  uint32_t patch_len;
  uint8_t original_bytes[15];
  bool hooked;
} jmp_hook_ctx;

enum jmp_hook_mode {
  JMP_MODE_BEST_SUITABLE,
  JMP_MODE_DISP32,
  JMP_MODE_ABSOLUTE,
  JMP_MODE_INDIRECT
};

enum jmp_hook_reg {
  JMP_REG_RAX,
  JMP_REG_RCX,
  JMP_REG_RDX,
  JMP_REG_RBX,
  JMP_REG_RSP,
  JMP_REG_RBP,
  JMP_REG_RSI,
  JMP_REG_RDI,
  JMP_REG_R8,
  JMP_REG_R9,
  JMP_REG_R10,
  JMP_REG_R11,
  JMP_REG_R12,
  JMP_REG_R13,
  JMP_REG_R14,
  JMP_REG_R15
};

bool jmp_hook(uintptr_t from, uintptr_t jmp_to, jmp_hook_ctx *state,
              jmp_hook_mode mode = JMP_MODE_BEST_SUITABLE, jmp_hook_reg reg = JMP_REG_RAX);
bool jmp_unhook(jmp_hook_ctx *state);

#endif // JMP_HOOKING_HPP