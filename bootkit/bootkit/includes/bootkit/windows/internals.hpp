#ifndef WINDOWS_INTERNALS_HPP_
#define WINDOWS_INTERNALS_HPP_

#include <cstdint>

#define POOL_FLAG_REQUIRED_START 0x0000000000000001U
#define POOL_FLAG_USE_QUOTA 0x0000000000000001U         // Charge quota
#define POOL_FLAG_UNINITIALIZED 0x0000000000000002U     // Don't zero-initialize allocation
#define POOL_FLAG_SESSION 0x0000000000000004U           // Use session specific pool
#define POOL_FLAG_CACHE_ALIGNED 0x0000000000000008U     // Cache aligned allocation
#define POOL_FLAG_RESERVED1 0x0000000000000010U         // Reserved for system use
#define POOL_FLAG_RAISE_ON_FAILURE 0x0000000000000020U  // Raise exception on failure
#define POOL_FLAG_NON_PAGED 0x0000000000000040U         // Non paged pool NX
#define POOL_FLAG_NON_PAGED_EXECUTE 0x0000000000000080U // Non paged pool executable
#define POOL_FLAG_PAGED 0x0000000000000100U             // Paged pool
#define POOL_FLAG_RESERVED2 0x0000000000000200U         // Reserved for system use
#define POOL_FLAG_RESERVED3 0x0000000000000400U         // Reserved for system use
#define POOL_FLAG_REQUIRED_END 0x0000000080000000U
#define POOL_FLAG_OPTIONAL_START 0x0000000100000000U
#define POOL_FLAG_SPECIAL_POOL 0x0000000100000000U // Make special pool allocation
#define POOL_FLAG_OPTIONAL_END 0x8000000000000000U

#define EPROCESS_VADROOT_OFFSET 0x7d8
#define VAD_LEFT_OFFSET 0x8
#define VAD_RIGHT_OFFSET 0x10
#define VAD_START_OFFSET 0x18
#define VAD_END_OFFSET 0x20
#define VAD_TYPE_OFFSET 0x40
#define VAD_SUBSECTION_OFFSET 0x40
#define CONTROL_AREA_FILEPTR_OFFSET 0x10
#define PEB_LDR_OFFSET 0x18
#define PEB_LDR_OFFSET_WOW64 0x0c
#define LDR_LOAD_ORDER_OFFSET 0x20
#define LDR_LOAD_ORDER_OFFSET_WOW64 0x14
#define LDR_DLL_BASE_OFFSET_64 0x30
#define LDR_DLL_BASE_OFFSET_32 0x18
#define LDR_DLL_NAME_OFFSET_64 0x58
#define LDR_DLL_NAME_OFFSET_32 0x24
#define EPROCESS_PEB_OFFSET 0x550
#define EPROCESS_WOW64_OFFSET 0x580

#define MDL_MAPPED_TO_SYSTEM_VA 0x0001
#define MDL_PAGES_LOCKED 0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE 0x0008
#define MDL_PARTIAL 0x0010
#define MDL_PARTIAL_HAS_BEEN_MAPPED 0x0020
#define MDL_IO_PAGE_READ 0x0040
#define MDL_WRITE_OPERATION 0x0080
#define MDL_LOCKED_PAGE_TABLES 0x0100
#define MDL_PARENT_MAPPED_SYSTEM_VA MDL_LOCKED_PAGE_TABLES
#define MDL_FREE_EXTRA_PTES 0x0200
#define MDL_DESCRIBES_AWE 0x0400
#define MDL_IO_SPACE 0x0800
#define MDL_NETWORK_HEADER 0x1000
#define MDL_MAPPING_CAN_FAIL 0x2000
#define MDL_PAGE_CONTENTS_INVARIANT 0x4000
#define MDL_ALLOCATED_MUST_SUCCEED MDL_PAGE_CONTENTS_INVARIANT
#define MDL_INTERNAL 0x8000

#define PAGE_SHIFT 12
#define PAGE_SIZE 4096

#define EXCEPTION_CONTINUE_SEARCH 0     // Continue searching for handlers
#define EXCEPTION_CONTINUE_EXECUTION -1 // Resume execution at the faulting instruction
#define EXCEPTION_EXECUTE_HANDLER 1     // Execute the handler block

#define CONST const

typedef unsigned char BYTE;
typedef int BOOL;
typedef BYTE BOOLEAN;
typedef char CCHAR;
typedef unsigned long DWORD;
typedef unsigned __int64 DWORDLONG;
typedef unsigned __int64 ULONG_PTR;
typedef ULONG_PTR *PULONG_PTR;
typedef ULONG_PTR DWORD_PTR;
typedef ULONG_PTR SIZE_T;
typedef SIZE_T *PSIZE_T;
typedef wchar_t WCHAR;
typedef WCHAR *PWSTR;
typedef WCHAR *LPWSTR;
typedef CONST WCHAR *LPCWSTR;
typedef WCHAR *LPWSTR;
typedef unsigned short USHORT;
typedef unsigned short WORD;
typedef USHORT *PUSHORT;
typedef long LONG;
typedef unsigned long ULONG;
typedef __int64 LONGLONG;
typedef LONG NTSTATUS;
typedef unsigned int DWORD32;
typedef unsigned __int64 DWORD64;
typedef float FLOAT;
typedef unsigned int ULONG32;
typedef unsigned __int64 ULONG64;
typedef void *LPVOID;
typedef void *PVOID;
typedef PVOID HANDLE;
typedef uint64_t POOL_FLAGS;
typedef unsigned __int64 ULONGLONG;

typedef union _LARGE_INTEGER {
  struct {
    DWORD LowPart;
    LONG HighPart;
  } DUMMYSTRUCTNAME;
  struct {
    DWORD LowPart;
    LONG HighPart;
  } u;
  LONGLONG QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER PHYSICAL_ADDRESS;

typedef struct _MM_COPY_ADDRESS {
  union {
    PVOID VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
  };
} MM_COPY_ADDRESS, *PMMCOPY_ADDRESS;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SUBSECTION {
  unsigned char *ControlArea;
  // ... other fields
} SUBSECTION, *PSUBSECTION;

typedef struct _OBJECT_NAME_INFORMATION {
  UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct {
  uint16_t Length;
  uint16_t MaximumLength;
  uint32_t Buffer;
} UNICODE_STRING32;

typedef struct {
  union {
    UNICODE_STRING unicode64;
    UNICODE_STRING32 unicode32;
  };
} UNICODE_STRINGX;

typedef struct _MDL {
  struct _MDL *Next;
  USHORT Size;
  USHORT MdlFlags;
  void *Process;
  PVOID MappedSystemVa;
  PVOID StartVa;
  ULONG ByteCount;
  ULONG ByteOffset;
} MDL, *PMDL;

typedef enum _POOL_TYPE {
  NonPagedPool,
  NonPagedPoolExecute = NonPagedPool,
  PagedPool,
  NonPagedPoolMustSucceed = NonPagedPool + 2,
  DontUseThisType,
  NonPagedPoolCacheAligned = NonPagedPool + 4,
  PagedPoolCacheAligned,
  NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
  MaxPoolType,
  NonPagedPoolBase = 0,
  NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
  NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
  NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
  NonPagedPoolSession = 32,
  PagedPoolSession = NonPagedPoolSession + 1,
  NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
  DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
  NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
  PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
  NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
  NonPagedPoolNx = 512,
  NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
  NonPagedPoolSessionNx = NonPagedPoolNx + 32,
} POOL_TYPE;

#define MM_COPY_MEMORY_PHYSICAL 1
#define MM_COPY_MEMORY_VIRTUAL 2

namespace ntoskrnl {
  HANDLE PsGetCurrentProcessId(void);
  void *PsGetCurrentProcess(void);
  void *PsGetProcessSectionBaseAddress(void *Process);
  NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, void *Process);
  void ObDereferenceObject(void *a);
  NTSTATUS MmCopyMemory(PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes,
                        ULONG Flags, PSIZE_T NumberOfBytesTransferred);
  PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect);
  void MmUnmapIoSpace(PVOID BaseAddress, SIZE_T NumberOfBytes);
  NTSTATUS ObQueryNameString(PVOID Object, POBJECT_NAME_INFORMATION ObjectNameInfo, ULONG Length,
                             ULONG *ReturnLength);
  PVOID ExAllocatePool2(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag);
  void ExFreePool(PVOID P);
  void *IoAllocateMdl(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer,
                      BOOLEAN ChargeQuota, void *Irp);
  void MmBuildMdlForNonPagedPool(void *MemoryDescriptorList);
  ULONG *MmGetMdlPfnArray(void *Mdl);
  PVOID MmMapLockedPagesSpecifyCache(void *MemoryDescriptorList, int AccessMode, int CacheType,
                                     PVOID RequestedAddress, ULONG BugCheckOnFailure,
                                     ULONG Priority);
  void IoFreeMdl(void *Mdl);
  BOOLEAN MmIsAddressValid(uint64_t VirtualAddress);
  void MmUnmapLockedPages(PVOID BaseAddress, void *MemoryDescriptorList);
  void MmInitializeMdl(void *MemoryDescriptorList, PVOID BaseVa, SIZE_T Length);
  PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
} // namespace ntoskrnl

#endif // WINDOWS_INTERNALS_HPP_