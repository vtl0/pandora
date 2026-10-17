#ifndef _UAPI_ASM_X86_IST_H
#define _UAPI_ASM_X86_IST_H

#include <cstdint>

struct ist_info {
  uint32_t signature;
  uint32_t command;
  uint32_t event;
  uint32_t perf_level;
};

#endif /* _UAPI_ASM_X86_IST_H */