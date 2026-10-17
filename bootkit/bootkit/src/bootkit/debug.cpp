#include <bootkit/debug.hpp>

#include <cstdint>

extern "C" {
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
}

void dbg::serial_print(const char *fmt, ...)
{
#if defined(_TEST_BUILD) || defined(_DEBUG)
  constexpr uint16_t LSR_PORT = 0x3FD;
  constexpr uint16_t DR_PORT = 0x3F8;
  constexpr uint16_t VMWARE_DR = 0x402;
  constexpr uint8_t LSR_EMPTY = 0x20;
  CHAR8 buf[256];
  VA_LIST marker;
  uint8_t status;

  VA_START(marker, fmt);
  AsciiVSPrint(buf, sizeof(buf), fmt, marker);

  if (fmt == nullptr)
    return;

  for (int i = 0; i < sizeof(buf) && buf[i]; i++) {
    do {
      __asm__ volatile("inb %1, %0\n\t"
                       "pause"
                       : "=a"(status)
                       : "Nd"(LSR_PORT));
    } while ((status & LSR_EMPTY) == 0);

    __asm__ volatile("outb %0, %1" ::"a"(buf[i]), "Nd"(DR_PORT));
  }
#endif // defined(_TEST_BUILD) || defined(_DEBUG)
}