#ifndef LINUX_KALLSYMS_HPP_
#define LINUX_KALLSYMS_HPP_

#include <concepts>
#include <cstddef>
#include <cstdint>

extern "C" {
#include <Library/BaseLib.h>
}

#define KSYM_NAME_LEN 512

namespace concepts {
  template<typename F>
  concept kallsyms_callback = requires(F func, const char *name, uintptr_t addr, char type) {
    { func(name, addr, type) } -> std::convertible_to<bool>;
  };
} // namespace concepts

namespace kallsyms {
  enum kallsyms_traits : uint32_t {
    TRAIT_ALIGN_4_BYTES = (1 << 0),
    TRAIT_ALIGN_8_BYTES = (1 << 1),
    TRAIT_NAME_LEN_U8 = (1 << 2),
    TRAIT_NAME_LEN_ULEB128 = (1 << 3),
    TRAIT_OFFSETS_PRECEDES_NUM_SYMS = (1 << 4),
    TRAIT_OFFSETS_POST_TOKEN_INDEX = (1 << 5),
    TRAIT_ADDR_ABSOLUTE = (1 << 6),
    TRAIT_ADDR_ABSOLUTE_PERCPU = (1 << 7),
    TRAIT_ADDR_BASE_DISPLACED = (1 << 8),
    TRAIT_ADDR_SELF_DISPLACED = (1 << 9),
    TRAIT_SEQS_OF_NAMES_AVAILABLE = (1 << 10)
  };

  enum kallsyms_query_mode : uint32_t {
    KALLSYMS_QUERY_DEREF_IF_PTR = (1 << 0),
    KALLSYMS_QUERY_FOR_DATA = (1 << 1),
    KALLSYMS_QUERY_FOR_CODE = (1 << 2),
    KALLSYMS_QUERY_FOR_RODATA = (1 << 3),
    KALLSYMS_QUERY_FOR_GLOBAL = (1 << 4),
    KALLSYMS_QUERY_FOR_LOCAL = (1 << 5),
    KALLSYMS_QUERY_FOR_WEAK = (1 << 6),
    KALLSYMS_QUERY_FOR_TYPE = (1 << 7)
  };

  enum kallsyms_err_t : uint32_t { KALLSYMS_SUCCESS, KALLSYMS_ERROR, KALLSYMS_SECONDARY_SUCCESS };

  struct ks {
    uint8_t *names;
    uint32_t *markers;
    const char *token_table;
    uint16_t *token_index;
    uint32_t *seqs_of_names;
    uintptr_t kallsyms_relative_base;

    union {
      uintptr_t *addresses;
      int32_t *offsets;
    };

    uint32_t traits;
    unsigned int num_syms;
    bool is_available;
  };

  struct sym_iter {
    unsigned int idx;
    unsigned int names_off;
  };

  inline ks ksms;

  bool find_layout(uintptr_t stext);
  uintptr_t get_address(unsigned int idx);
  uint32_t get_length(uint8_t *&c);
  unsigned int get_name(char *buf, size_t buf_size, unsigned int names_offset,
                        char *type = nullptr);
  kallsyms_err_t find_by_name(const char *name, uintptr_t *addr_out, uint32_t query_mode = 0,
                              char wanted_type = 0, char *found_type = nullptr);

  inline bool kallsyms_available()
  {
    return ksms.is_available;
  }

  template<concepts::kallsyms_callback F>
  bool for_each(F &&callback)
  {
    char name[KSYM_NAME_LEN];
    uint8_t *entry;
    uint32_t len;
    unsigned int names_off;
    unsigned int idx;
    bool done;

    names_off = 0;
    idx = 0;
    done = false;
    while (idx < ksms.num_syms) {
      uintptr_t addr;
      char type;

      get_name(name, sizeof(name), names_off, &type);
      addr = get_address(idx);

      done = callback(name, addr, type);
      if (done)
        return true;

      entry = ksms.names + names_off;
      len = get_length(entry);
      names_off = static_cast<unsigned int>(entry - ksms.names) + len;
      idx++;
    }

    return false;
  }
} // namespace kallsyms

#endif // LINUX_KALLSYMS_HPP_