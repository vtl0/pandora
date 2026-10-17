#ifndef INTERFACES_HPP_
#define INTERFACES_HPP_

extern "C" {
#include <Protocol/Runtime.h>
#include <Protocol/Cpu.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextInEx.h>
#include <Protocol/Shell.h>
#include <Protocol/DevicePathToText.h>
};

namespace i {
  inline EFI_SIMPLE_TEXT_INPUT_PROTOCOL *simple_text_input;
  inline EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *simple_text_input_ex;
  inline EFI_RUNTIME_ARCH_PROTOCOL *g_runtime;
  inline EFI_CPU_ARCH_PROTOCOL *cpu_protocol;
  inline EFI_SHELL_PROTOCOL *shell_protocol;
  inline EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *device_path_protocol;
} // namespace i

#endif // INTERFACES_HPP_