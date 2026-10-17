#include <bootkit/binary/heuristic.hpp>
#include <bootkit/binary/identifier.hpp>
#include <bootkit/binary/pe.hpp>
#include <bootkit/general.hpp>

extern "C" {
#include <Protocol/LoadedImage.h>
}

image_type identify_image(EFI_HANDLE image, uintptr_t *p_base, size_t *p_size)
{
  EFI_LOADED_IMAGE_PROTOCOL *image_protocol;
  uintptr_t base;
  size_t size;

  if (EFI_ERROR(g::bs->HandleProtocol(image, &guid::loaded_image_protocol,
                                      reinterpret_cast<void **>(&image_protocol)))) {
    if (p_base)
      *p_base = 0;
    if (p_size)
      *p_size = 0;
    return UNKNOWN_IMAGE;
  }

  base = reinterpret_cast<uintptr_t>(image_protocol->ImageBase);
  size = image_protocol->ImageSize;
  if (p_base)
    *p_base = base;
  if (p_size)
    *p_size = size;
  if (!base || !size)
    return UNKNOWN_IMAGE;

  if (heuristic::is_systemd_stub(base, size)) {
    if (heuristic::is_uki(base, size))
      return SYSTEMD_STUB_UKI;
    return SYSTEMD_STUB;
  }
  if (heuristic::is_uki(base, size))
    return STUB_UKI;
  if (heuristic::is_grub(base, size))
    return GRUB;
  if (heuristic::is_systemd_boot(base, size))
    return SYSTEMD_BOOT;
  if (heuristic::is_bzimage(base, size))
    return BZIMAGE;
  if (heuristic::is_bootmgfw(base, size))
    return BOOTMGFW;
  // I think this is never loaded through LoadImage
  if (heuristic::is_winload(base, size))
    return WINLOAD;
  if (heuristic::is_veracrypt(base, size))
    return VERACRYPT;
  if (heuristic::is_shimx64(base, size))
    return SHIMLOADER;

  return UNKNOWN_IMAGE;
}