#ifndef CR0_HPP_
#define CR0_HPP_

#include <bootkit/arch/x86/x86.hpp>

#include <cstdint>

extern "C" {
#include <Library/BaseLib.h>
}

#define REG_GET 0
#define REG_SET 1
#define REG_AND 2
#define REG_OR 3

class set_cr0 {
private:
  uint64_t cr0_ctl(int mode, uint64_t value);
  uint64_t cr0;

public:
  set_cr0(int mode, uint64_t value) : cr0(cr0_ctl(mode, value)) {};
  ~set_cr0()
  {
    AsmWriteCr0(cr0);
  };
};

#define CR0(mode, val)                                                                             \
  if (bool __raii_lifetime = true)                                                                 \
    for (set_cr0 __raii_hack(mode, val); __raii_lifetime; __raii_lifetime = false)

#endif // CR0_HPP_