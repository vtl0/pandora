#ifndef SERVICE_PTR_HPP_
#define SERVICE_PTR_HPP_

#include <bootkit/general.hpp>

template<typename func_type>
func_type swap_service_ptr(EFI_TABLE_HEADER *service_header, func_type *service_function, func_type function)
{
  func_type original;
  EFI_TPL tpl;

  if (service_header == nullptr || service_function == nullptr || function == nullptr)
    return nullptr;

  tpl = g::bs->RaiseTPL(TPL_HIGH_LEVEL);

  original = *service_function;
  *service_function = function;
  service_header->CRC32 = 0;
  g::bs->CalculateCrc32(reinterpret_cast<void *>(service_header), service_header->HeaderSize,
                        &service_header->CRC32);
  g::bs->RestoreTPL(tpl);

  return original;
}
#endif // SERVICE_PTR_HPP