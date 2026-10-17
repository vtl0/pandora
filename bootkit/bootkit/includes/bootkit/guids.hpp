#ifndef GUIDS_HPP_
#define GUIDS_HPP_

extern "C" {
#include <Protocol/Cpu.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MemoryAttribute.h>
#include <Protocol/Runtime.h>
}

namespace guid {
  inline EFI_GUID runtime_arch_protocol = EFI_RUNTIME_ARCH_PROTOCOL_GUID;
  inline EFI_GUID loaded_image_protocol = EFI_LOADED_IMAGE_PROTOCOL_GUID;
  inline EFI_GUID device_path_protocol = EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;
  inline EFI_GUID cpu_arch_protocol = EFI_CPU_ARCH_PROTOCOL_GUID;
  inline EFI_GUID memory_protocol = EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID;
}; // namespace guid

#endif // GUIDS_HPP_