#ifndef DEBUG_HPP_
#define DEBUG_HPP_

extern "C" {
#include <Base.h>
#include <Library/DebugLib.h>
}

#if defined(_TEST_BUILD) || defined(_DEBUG)

extern "C" {
#include <Library/PrintLib.h>
}

namespace dbg {
  template<typename... Args>
  inline void print(UINTN error_level, const char *format, Args... args)
  {
    DebugPrint(error_level, format, args...);
  }
}; // namespace dbg

#define D(x) x

#else
namespace dbg {
  inline void print(UINTN error_level, const char *format, ...)
  {
    return;
  }
}; // namespace dbg

#define D(x)

#endif // defined(_TEST_BUILD) || defined(_DEBUG)

namespace dbg {
  void serial_print(const char *str, ...);
} // namespace dbg
#endif // DEBUG_HPP_