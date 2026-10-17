#include <bootkit/general.hpp>
#include <bootkit/hooks/shim.hpp>

void hooks::shim::hook_system_services(EFI_SYSTEM_TABLE* local_systab)
{
  jmp_unhook(&hook_system_services_ctx);


}

void hooks::shim::unhook_system_services()
{
  jmp_unhook(&unhook_system_services_ctx);

}