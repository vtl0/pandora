#ifndef STRING_HPP_
#define STRING_HPP_

extern "C" {
#include <Uefi/UefiBaseType.h>
}

inline CHAR16 *operator"" _uefi(const wchar_t * str, size_t)
{
  return reinterpret_cast<CHAR16 *>(const_cast<wchar_t *>(str));
}
inline CHAR16 *operator"" _uefi(const char16_t *str, size_t)
{
  return reinterpret_cast<CHAR16 *>(const_cast<char16_t *>(str));
}

#endif // STRING_HPP_