#ifndef UEFI_INTERNALS_HPP_
#define UEFI_INTERNALS_HPP_

#include <bootkit/general.hpp>
#include <bootkit/interfaces.hpp>

#include <concepts>

extern "C" {
#include <Protocol/Runtime.h>
};

typedef struct {
  LIST_ENTRY Link;
  UINT64 TriggerTime;
  UINT64 Period;
} TIMER_EVENT_INFO;

#define EVENT_SIGNATURE SIGNATURE_32('e', 'v', 'n', 't')
typedef struct {
  UINTN Signature;
  UINT32 Type;
  UINT32 SignalCount;
  LIST_ENTRY SignalLink;
  EFI_TPL NotifyTpl;
  EFI_EVENT_NOTIFY NotifyFunction;
  VOID *NotifyContext;
  EFI_GUID EventGroup;
  LIST_ENTRY NotifyLink;
  UINT8 ExFlag;
  EFI_RUNTIME_EVENT_ENTRY RuntimeData;
  TIMER_EVENT_INFO Timer;
} IEVENT;

namespace concepts {
  template<typename F>
  concept event_callback = requires(F func, IEVENT *event) {
    { func(event) } -> std::convertible_to<BOOLEAN>;
  };

  template<typename F>
  concept image_callback = requires(F func, EFI_RUNTIME_IMAGE_ENTRY *image) {
    { func(image) } -> std::convertible_to<BOOLEAN>;
  };
} // namespace concepts

template<concepts::event_callback F>
BOOLEAN iterate_events(F &&callback)
{
  static LIST_ENTRY *head;
  LIST_ENTRY *link;
  IEVENT *event;
  EFI_TPL tpl;
  BOOLEAN found;

  found = FALSE;
  tpl = g::bs->RaiseTPL(TPL_HIGH_LEVEL);
  if (head == nullptr) {
    //EFI_RUNTIME_EVENT_ENTRY *rt_event_entry;
    //LIST_ENTRY *rt_head;
    // get_event_signal_queue worked for every firmware image I tested agaisnt
    head = reinterpret_cast<LIST_ENTRY *>(heuristic::get_event_signal_queue());
    if (head == 0 && i::g_runtime == nullptr) {
      EFI_STATUS status;
      status = g::bs->LocateProtocol(&guid::runtime_arch_protocol, nullptr,
                                     reinterpret_cast<void **>(&i::g_runtime));
      if (status != EFI_SUCCESS || i::g_runtime == nullptr) {
        return FALSE;
      }
    }
    else {
      // TODO
    }
    if (head == nullptr) {
      return FALSE;
    }
  }

  for (link = head->ForwardLink; link != head; link = link->ForwardLink) {
    event = CR(link, IEVENT, SignalLink, EVENT_SIGNATURE);
    found |= callback(event);
  }

  g::bs->RestoreTPL(tpl);
  return found;
}

template<concepts::image_callback F>
BOOLEAN iterate_images(F &&callback)
{
  LIST_ENTRY *current;
  EFI_TPL tpl;
  BOOLEAN found;

  if (i::g_runtime == nullptr) {
    EFI_STATUS status;
    status = g::bs->LocateProtocol(&guid::runtime_arch_protocol, nullptr,
                                   reinterpret_cast<void **>(&i::g_runtime));
    if (status != EFI_SUCCESS || i::g_runtime == nullptr) {
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
    if (img == nullptr)
      continue;

    found |= callback(img);
  }

  g::bs->RestoreTPL(tpl);

  return found;
}
#endif // UEFI_INTERNALS_HPP_