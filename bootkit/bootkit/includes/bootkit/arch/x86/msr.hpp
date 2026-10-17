#ifndef X86_MSR_HPP
#define X86_MSR_HPP

#define CPUID_EXTENDED_PROC_FEATURES 0x80000001
#define CPUID_NXE_BIT 0b100000000000000000000

#define MSR_EFER 0xC0000080
#define EFER_NXE_BIT 0b100000000000

bool nxe_supported();
void nxe_enable(bool enable);
bool nxe_enabled();

#endif // X86_MSR_HPP