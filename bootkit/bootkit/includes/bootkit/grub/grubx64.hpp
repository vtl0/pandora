#ifndef GRUBX64_HPP_
#define GRUBX64_HPP_

#include <cstdint>

#define GRUB_CRYPTODISK_MAX_KEYLEN 128
#define GRUB_CRYPTODISK_MAX_PASSPHRASE 256

namespace grubx64 {
  struct grub_dl {
    char *name;
    int ref_count;
    int persistent;
    void *dep;
    void *segment;
    void *symtab;
    uint64_t symsize;
    void (*init)(struct grub_dl *mod);
    void (*fini)(void);
#if !defined(__i386__) && !defined(__x86_64__)
    void *got;
    void *gotptr;
    void *tramp;
    void *trampptr;
#endif
#ifdef __mips__
    grub_uint32_t *reginfo;
#endif
    void *base;
    uint64_t sz;
    struct grub_dl *next;
  };
  struct grub_dl_2_14 {
    char *name;
    uint64_t ref_count;
    int persistent;
    void *dep;
    void *segment;
    void *symtab;
    uint64_t symsize;
    void (*init)(struct grub_dl *mod);
    void (*fini)(void);
#if !defined(__i386__) && !defined(__x86_64__)
    void *got;
    void *gotptr;
    void *tramp;
    void *trampptr;
#endif
#ifdef __mips__
    grub_uint32_t *reginfo;
#endif
    void *base;
    uint64_t sz;
    struct grub_dl_2_14 *next;
  };
  // https://elixir.bootlin.com/grub/2.00/source/grub-core/gensymlist.sh#L52
  struct symtab {
    const char *name;
    void *addr;
    int isfunc;
  };
  enum grub_err_t {
    GRUB_ERR_NONE = 0,
    GRUB_ERR_TEST_FAILURE,
    GRUB_ERR_BAD_MODULE,
    GRUB_ERR_OUT_OF_MEMORY,
    GRUB_ERR_BAD_FILE_TYPE,
    GRUB_ERR_FILE_NOT_FOUND,
    GRUB_ERR_FILE_READ_ERROR,
    GRUB_ERR_BAD_FILENAME,
    GRUB_ERR_UNKNOWN_FS,
    GRUB_ERR_BAD_FS,
    GRUB_ERR_BAD_NUMBER,
    GRUB_ERR_OUT_OF_RANGE,
    GRUB_ERR_UNKNOWN_DEVICE,
    GRUB_ERR_BAD_DEVICE,
    GRUB_ERR_READ_ERROR,
    GRUB_ERR_WRITE_ERROR,
    GRUB_ERR_UNKNOWN_COMMAND,
    GRUB_ERR_INVALID_COMMAND,
    GRUB_ERR_BAD_ARGUMENT,
    GRUB_ERR_BAD_PART_TABLE,
    GRUB_ERR_UNKNOWN_OS,
    GRUB_ERR_BAD_OS,
    GRUB_ERR_NO_KERNEL,
    GRUB_ERR_BAD_FONT,
    GRUB_ERR_NOT_IMPLEMENTED_YET,
    GRUB_ERR_SYMLINK_LOOP,
    GRUB_ERR_BAD_COMPRESSED_DATA,
    GRUB_ERR_MENU,
    GRUB_ERR_TIMEOUT,
    GRUB_ERR_IO,
    GRUB_ERR_ACCESS_DENIED,
    GRUB_ERR_EXTRACTOR,
    GRUB_ERR_NET_BAD_ADDRESS,
    GRUB_ERR_NET_ROUTE_LOOP,
    GRUB_ERR_NET_NO_ROUTE,
    GRUB_ERR_NET_NO_ANSWER,
    GRUB_ERR_NET_NO_CARD,
    GRUB_ERR_WAIT,
    GRUB_ERR_BUG,
    GRUB_ERR_NET_PORT_CLOSED,
    GRUB_ERR_NET_INVALID_RESPONSE,
    GRUB_ERR_NET_UNKNOWN_ERROR,
    GRUB_ERR_NET_PACKET_TOO_BIG,
    GRUB_ERR_NET_NO_DOMAIN,
    GRUB_ERR_EOF,
    GRUB_ERR_BAD_SIGNATURE,
    GRUB_ERR_BAD_FIRMWARE,
    GRUB_ERR_STILL_REFERENCED,
    GRUB_ERR_RECURSION_DEPTH
  };
  typedef enum {
    GPG_ERR_NO_ERROR,
    GPG_ERR_BAD_MPI,
    GPG_ERR_BAD_SECKEY,
    GPG_ERR_BAD_SIGNATURE,
    GPG_ERR_CIPHER_ALGO,
    GPG_ERR_CONFLICT,
    GPG_ERR_DECRYPT_FAILED,
    GPG_ERR_DIGEST_ALGO,
    GPG_ERR_GENERAL,
    GPG_ERR_INTERNAL,
    GPG_ERR_INV_ARG,
    GPG_ERR_INV_CIPHER_MODE,
    GPG_ERR_INV_FLAG,
    GPG_ERR_INV_KEYLEN,
    GPG_ERR_INV_OBJ,
    GPG_ERR_INV_OP,
    GPG_ERR_INV_SEXP,
    GPG_ERR_INV_VALUE,
    GPG_ERR_MISSING_VALUE,
    GPG_ERR_NO_ENCRYPTION_SCHEME,
    GPG_ERR_NO_OBJ,
    GPG_ERR_NO_PRIME,
    GPG_ERR_NO_SIGNATURE_SCHEME,
    GPG_ERR_NOT_FOUND,
    GPG_ERR_NOT_IMPLEMENTED,
    GPG_ERR_NOT_SUPPORTED,
    GPG_ERR_PUBKEY_ALGO,
    GPG_ERR_SELFTEST_FAILED,
    GPG_ERR_TOO_SHORT,
    GPG_ERR_UNSUPPORTED,
    GPG_ERR_WEAK_KEY,
    GPG_ERR_WRONG_KEY_USAGE,
    GPG_ERR_WRONG_PUBKEY_ALGO,
    GPG_ERR_OUT_OF_MEMORY,
    GPG_ERR_TOO_LARGE,
    GPG_ERR_ENOMEM
  } gpg_err_code_t;

  typedef grub_dl *grub_dl_t;
  typedef grub_dl_2_14 *grub_dl_t_2_14;
  typedef gpg_err_code_t gpg_error_t;
  typedef gpg_error_t gcry_error_t;
  typedef gpg_err_code_t gcry_err_code_t;
  typedef gcry_error_t gcry_err_code_tg;

  inline uintptr_t data_section_address;
  inline size_t data_section_size;

  // I haven't ever seen a GRUB 2 build with .rodata
  inline uintptr_t rodata_section_address;
  inline size_t rodata_section_size;

  inline uintptr_t text_section_address;
  inline size_t text_section_size;

  inline symtab *symtab_array;
  inline size_t symtab_count;
  inline uintptr_t grub_dl_load_core_noinit_addr;

  inline uint8_t dumped_keys[4][GRUB_CRYPTODISK_MAX_KEYLEN];
  inline uint8_t dumped_keys_len[4];
  inline int dumped_keys_index;

  bool init_grub_internals(uintptr_t grub_module_base, size_t module_length);
  bool find_symtab();
  uintptr_t find_symbol(const char *name);
} // namespace grub

#endif // GRUBX64_HPP_