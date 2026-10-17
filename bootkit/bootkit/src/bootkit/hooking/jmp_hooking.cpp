#include <bootkit/arch/x86/control_register.hpp>
#include <bootkit/arch/x86/x86.hpp>
#include <bootkit/general.hpp>
#include <bootkit/hooking/jmp_hooking.hpp>

extern "C" {
#include <Library/BaseMemoryLib.h>
#include <Protocol/Cpu.h>
#include <Protocol/MemoryAttribute.h>
}

bool jmp_hook(uintptr_t from, uintptr_t jmp_to, jmp_hook_ctx *state, jmp_hook_mode mode,
              jmp_hook_reg reg)
{
  uint8_t *patch_ptr;
  int64_t disp;
  bool outside_disp32_range;

  if (from == 0 || jmp_to == 0 || state == nullptr)
    return false;

  if (state->hooked)
    return false;

  disp = static_cast<int64_t>(jmp_to) - static_cast<int64_t>(from + 5);
  patch_ptr = reinterpret_cast<uint8_t *>(from);
  state->from = from;
  outside_disp32_range = (disp < INT32_MIN || disp > INT32_MAX);
  if (outside_disp32_range || mode == JMP_MODE_ABSOLUTE) {
    if (mode == JMP_MODE_ABSOLUTE) {
      bool extended = (reg >= JMP_REG_R8);
      uint8_t target_reg = reg & 0b111;

      if (reg == JMP_REG_RSP || reg == JMP_REG_RBP)
        return false;

      state->patch_len = extended ? 13 : 12;
      CopyMem(state->original_bytes, patch_ptr, state->patch_len);

      CR0(REG_AND, ~CR0_WP)
      {
        patch_ptr[0] = P_REX | P_W_BIT | (extended ? P_B_BIT : 0);
        patch_ptr[1] = 0xB8 | target_reg; // movabs reg,
        *reinterpret_cast<uintptr_t *>(&patch_ptr[2]) = jmp_to;
        if (extended) {
          patch_ptr[10] = P_REX | P_B_BIT;
          patch_ptr[11] = 0xFF; // jmp reg
          patch_ptr[12] = 0xE0 | target_reg;
        }
        else {
          patch_ptr[10] = 0xFF; // jmp reg
          patch_ptr[11] = 0xE0 | target_reg;
        }
      }
    }
    else {
      // JMP_MODE_INDIRECT
      state->patch_len = 14;
      CopyMem(state->original_bytes, patch_ptr, state->patch_len);

      CR0(REG_AND, ~CR0_WP)
      {
        patch_ptr[0] = 0xFF;
        patch_ptr[1] = 0x25;
        *reinterpret_cast<int32_t *>(&patch_ptr[2]) = 0;
        *reinterpret_cast<uintptr_t *>(&patch_ptr[6]) = jmp_to;
      }
    }
  }
  else {
    state->patch_len = 5;
    CopyMem(state->original_bytes, patch_ptr, state->patch_len);

    CR0(REG_AND, ~CR0_WP)
    {
      patch_ptr[0] = 0xE9;
      *reinterpret_cast<int32_t *>(&patch_ptr[1]) = disp;
    }
  }

  state->hooked = true;
  return true;
}

bool jmp_unhook(jmp_hook_ctx *state)
{
  uint8_t *from;

  if (state == nullptr)
    return false;

  if (state->from == 0 || state->hooked == false)
    return false;

  from = reinterpret_cast<uint8_t *>(state->from);
  CR0(REG_AND, ~CR0_WP)
  {
    CopyMem(from, state->original_bytes, state->patch_len);
  }

  state->hooked = false;
  return true;
}