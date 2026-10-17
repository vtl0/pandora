#include <bootkit/arch/x86/control_register.hpp>

#include <cstdint>

extern "C" {
#include <Library/BaseLib.h>
}

uint64_t set_cr0::cr0_ctl(int mode, uint64_t value)
{
  uint64_t current = AsmReadCr0();

  switch (mode) {
  case REG_GET:
    break;
  case REG_SET:
    AsmWriteCr0(value);
    break;
  case REG_AND:
    AsmWriteCr0(current & value);
    break;
  case REG_OR:
    AsmWriteCr0(current | value);
    break;
  }

  return current;
}