#ifndef SHIM_HOOKS_HPP_
#define SHIM_HOOKS_HPP_

#include <bootkit/hooking/jmp_hooking.hpp>

#include <cstdint>


namespace hooks::shim {
  inline jmp_hook_ctx hook_system_services_ctx;
  inline jmp_hook_ctx unhook_system_services_ctx;
  inline uintptr_t hook_system_services_addr;
  inline uintptr_t unhook_system_services_addr;
  
  void hook_system_services(EFI_SYSTEM_TABLE *local_systab);
  void unhook_system_services();
}

#endif // SHIM_HOOKS_HPP_