#include <bootkit/arch/x86/memory.hpp>
#include <bootkit/binary/heuristic.hpp>
#include <bootkit/linux/kallsyms.hpp>
#include <bootkit/linux/vmlinux.hpp>

#include <cstddef>
#include <cstdint>

bool kallsyms::find_layout(uintptr_t stext)
{
  uintptr_t max;

  max = stext + pt::mapped_range_from(stext);
  if (max - stext < 4)
    return false;

  for (uintptr_t i = stext; i <= max - 4; i += sizeof(uint32_t)) {
    ks _ksms = {};

    if (heuristic::is_valid_kallsyms(i, &_ksms)) {
      ksms = _ksms;
      ksms.is_available = true;
      return true;
    }
  }

  return false;
}

uint32_t kallsyms::get_length(uint8_t *&c)
{
  uint32_t len;

  if (ksms.traits & TRAIT_NAME_LEN_U8) {
    len = static_cast<uint32_t>(c[0]);
    c++;
    return len;
  }

  len = static_cast<uint32_t>(c[0] & 0b01111111);

  // ULEB128 signals a following byte if MSB is set. Linux kernel limits
  // size to 0x3FFF, 2 bytes and unlikely to ever need increasing
  // https://elixir.bootlin.com/linux/v6.9.7/source/scripts/kallsyms.c#L432
  if (c[0] & 0b10000000) {
    len |= static_cast<uint32_t>(c[1]) << 7;
    c++;
  }

  c++;
  return len;
}

uintptr_t kallsyms::get_address(unsigned int idx)
{
  if (ksms.traits & TRAIT_ADDR_SELF_DISPLACED)
    return reinterpret_cast<uintptr_t>(&ksms.offsets[idx]) + ksms.offsets[idx];

  if (ksms.traits & TRAIT_ADDR_BASE_DISPLACED) {
    if (ksms.traits & TRAIT_ADDR_ABSOLUTE_PERCPU) {
      // https://elixir.bootlin.com/linux/v6.9.7/source/kernel/kallsyms.c#L159
      // https://elixir.bootlin.com/linux/v6.9.7/source/kernel/kallsyms.c#L163
      if (ksms.offsets[idx] >= 0)
        return static_cast<uintptr_t>(ksms.offsets[idx]);

      return ksms.kallsyms_relative_base - 1 - ksms.offsets[idx];
    }
    // https://elixir.bootlin.com/linux/v6.9.7/source/kernel/kallsyms.c#L156
    return ksms.kallsyms_relative_base + static_cast<uint32_t>(ksms.offsets[idx]);
  }

  return ksms.addresses[idx];
}

unsigned int kallsyms::get_name(char *buf, size_t buf_size, unsigned int names_offset, char *type)
{
  uint8_t *entry;
  uint32_t tokens;
  int buf_pos;

  if (!buf || !buf_size)
    return 0;

  entry = ksms.names + names_offset;
  tokens = get_length(entry);
  buf_pos = 0;
  for (uint32_t i = 0; i < tokens; i++) {
    const char *token = ksms.token_table + ksms.token_index[entry[i]];
    for (int k = 0; token[k]; k++) {
      // first byte is the type
      if (k == 0 && i == 0) {
        if (type != nullptr)
          *type = token[k];
        continue;
      }

      if (buf_pos < buf_size - 1)
        buf[buf_pos] = token[k];
      buf_pos++;
    }
  }

  if (buf_pos < buf_size)
    buf[buf_pos] = '\0';
  else
    buf[buf_size - 1] = '\0';

  return buf_pos;
}

kallsyms::kallsyms_err_t kallsyms::find_by_name(const char *name, uintptr_t *address,
                                                uint32_t query_mode, char wanted_type,
                                                char *found_type)
{
  kallsyms_err_t ret;
  bool found = false;

  ret = KALLSYMS_ERROR;
  for_each([&](const char *current_name, uintptr_t addr, char type) -> bool {
    uintptr_t val;

    if (query_mode & KALLSYMS_QUERY_FOR_TYPE && type != wanted_type)
      return false;

    if (query_mode & KALLSYMS_QUERY_FOR_GLOBAL && !(type >= 'A' && type <= 'Z'))
      return false;

    if (query_mode & KALLSYMS_QUERY_FOR_LOCAL && !(type >= 'a' && type <= 'z'))
      return false;

    if (query_mode & KALLSYMS_QUERY_FOR_CODE && type != 'T' && type != 't' && type != 'W' &&
        type != 'w')
      return false;

    if (query_mode & KALLSYMS_QUERY_FOR_DATA && type != 'D' && type != 'd' && type != 'B' &&
        type != 'b' && type != 'R' && type != 'r')
      return false;

    if (query_mode & KALLSYMS_QUERY_FOR_WEAK && type != 'W' && type != 'w')
      return false;

    if (query_mode & KALLSYMS_QUERY_FOR_RODATA && type != 'R' && type != 'r')
      return false;

    if (AsciiStrCmp(current_name, name) != 0)
      return false;

    val = addr;
    if (query_mode & KALLSYMS_QUERY_DEREF_IF_PTR) {
      if (!pt::is_page_present(val))
        ret = KALLSYMS_SECONDARY_SUCCESS;
      else if (type == 'D' || type == 'd' || type == 'B' || type == 'b') {
        val = *reinterpret_cast<uintptr_t *>(addr);
        ret = KALLSYMS_SUCCESS;
      }
    }
    else
      ret = KALLSYMS_SUCCESS;

    if (found_type != nullptr)
      *found_type = type;

    *address = val;
    found = true;
    return true;
  });

  return ret;
}