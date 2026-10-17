#include <bootkit/arch/x86/msr.hpp>

#include <cstdint>
#include <cpuid.h>

extern "C" {
#include <Library/BaseLib.h>
#include <Register/Intel/ArchitecturalMsr.h>
}

bool nxe_supported()
{
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;

  __get_cpuid_count(CPUID_EXTENDED_PROC_FEATURES, 0, &eax, &ebx, &ecx, &edx);
  return edx & CPUID_NXE_BIT;
}

void nxe_enable(bool enable)
{
  uint64_t val = AsmReadMsr64(MSR_EFER);
  val = enable ? val | EFER_NXE_BIT : val & ~EFER_NXE_BIT;
  AsmWriteMsr64(MSR_EFER, val);
}

bool nxe_enabled()
{
  return AsmReadMsr64(MSR_EFER) & EFER_NXE_BIT;
}