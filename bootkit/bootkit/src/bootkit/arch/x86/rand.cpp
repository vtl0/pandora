#include <bootkit/arch/x86/rand.hpp>
#include <bootkit/utils/rand/splitmix64.hpp>

#include <cstdint>
#include <cpuid.h>

static bool cpu_supports_rdseed()
{
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;

  if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
    return false;

  return ebx & bit_RDSEED;
}

static bool cpu_supports_rdrand(void)
{
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;

  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
    return false;

  return ecx & bit_RDRND;
}

uint64_t rand64()
{
  uint64_t random_value;

  if (cpu_supports_rdseed()) {
    for (int i = 0; i < 100; i++) {
      uint8_t cf;

      __asm__ volatile("rdseed %0; setc %1" : "=r"(random_value), "=q"(cf)::"cc");
      if (cf)
        return random_value;
    }
  }

  if (cpu_supports_rdrand()) {
    for (int i = 0; i < 100; i++) {
      uint8_t cf;

      __asm__ volatile("rdrand %0; setc %1" : "=r"(random_value), "=q"(cf)::"cc");
      if (cf)
        return random_value;
    }
  }

  random_value = splitmix64(__rdtsc());
  return random_value;
}
