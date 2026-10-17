#ifndef ASM_X86_BOOTPARAM_HPP_
#define ASM_X86_BOOTPARAM_HPP_

#include <linux/uapi/asm/ist.hpp>
#include <linux/uapi/linux/apm_bios.hpp>
#include <linux/uapi/linux/edd.hpp>
#include <linux/uapi/linux/screen_info.hpp>
#include <linux/uapi/video/edid.hpp>

#define SETUP_NONE 0
#define SETUP_E820_EXT 1
#define SETUP_DTB 2
#define SETUP_PCI 3
#define SETUP_EFI 4
#define SETUP_APPLE_PROPERTIES 5
#define SETUP_JAILHOUSE 6
#define SETUP_CC_BLOB 7
#define SETUP_IMA 8
#define SETUP_RNG_SEED 9
#define SETUP_ENUM_MAX SETUP_RNG_SEED

#define SETUP_INDIRECT (1 << 31)
#define SETUP_TYPE_MAX (SETUP_ENUM_MAX | SETUP_INDIRECT)

#define RAMDISK_IMAGE_START_MASK 0x07FF
#define RAMDISK_PROMPT_FLAG 0x8000
#define RAMDISK_LOAD_FLAG 0x4000

#define LOADED_HIGH (1 << 0)
#define KASLR_FLAG (1 << 1)
#define QUIET_FLAG (1 << 5)
#define KEEP_SEGMENTS (1 << 6)
#define CAN_USE_HEAP (1 << 7)

#define XLF_KERNEL_64 (1 << 0)
#define XLF_CAN_BE_LOADED_ABOVE_4G (1 << 1)
#define XLF_EFI_HANDOVER_32 (1 << 2)
#define XLF_EFI_HANDOVER_64 (1 << 3)
#define XLF_EFI_KEXEC (1 << 4)
#define XLF_5LEVEL (1 << 5)
#define XLF_5LEVEL_ENABLED (1 << 6)

struct setup_data {
  uint64_t next;
  uint32_t type;
  uint32_t len;
  uint8_t data[];
};

struct setup_indirect {
  uint32_t type;
  uint32_t reserved; /* Reserved, must be set to zero. */
  uint64_t len;
  uint64_t addr;
};

struct setup_header {
  uint8_t setup_sects;
  uint16_t root_flags;
  uint32_t syssize;
  uint16_t ram_size;
  uint16_t vid_mode;
  uint16_t root_dev;
  uint16_t boot_flag;
  uint16_t jump;
  uint32_t header;
  uint16_t version;
  uint32_t realmode_swtch;
  uint16_t start_sys_seg;
  uint16_t kernel_version;
  uint8_t type_of_loader;
  uint8_t loadflags;
  uint16_t setup_move_size;
  uint32_t code32_start;
  uint32_t ramdisk_image;
  uint32_t ramdisk_size;
  uint32_t bootsect_kludge;
  uint16_t heap_end_ptr;
  uint8_t ext_loader_ver;
  uint8_t ext_loader_type;
  uint32_t cmd_line_ptr;
  uint32_t initrd_addr_max;
  uint32_t kernel_alignment;
  uint8_t relocatable_kernel;
  uint8_t min_alignment;
  uint16_t xloadflags;
  uint32_t cmdline_size;
  uint32_t hardware_subarch;
  uint64_t hardware_subarch_data;
  uint32_t payload_offset;
  uint32_t payload_length;
  uint64_t setup_data;
  uint64_t pref_address;
  uint32_t init_size;
  uint32_t handover_offset;
  uint32_t kernel_info_offset;
} __attribute__((packed));

struct sys_desc_table {
  uint16_t length;
  uint8_t table[14];
};

struct olpc_ofw_header {
  uint32_t ofw_magic; /* OFW signature */
  uint32_t ofw_version;
  uint32_t cif_handler; /* callback into OFW */
  uint32_t irq_desc_table;
} __attribute__((packed));

struct efi_info {
  uint32_t efi_loader_signature;
  uint32_t efi_systab;
  uint32_t efi_memdesc_size;
  uint32_t efi_memdesc_version;
  uint32_t efi_memmap;
  uint32_t efi_memmap_size;
  uint32_t efi_systab_hi;
  uint32_t efi_memmap_hi;
};

#define E820_MAX_ENTRIES_ZEROPAGE 128

struct boot_e820_entry {
  uint64_t addr;
  uint64_t size;
  uint32_t type;
} __attribute__((packed));

#define JAILHOUSE_SETUP_REQUIRED_VERSION 1

struct jailhouse_setup_data {
  struct {
    uint16_t version;
    uint16_t compatible_version;
  } __attribute__((packed)) hdr;
  struct {
    uint16_t pm_timer_address;
    uint16_t num_cpus;
    uint64_t pci_mmconfig_base;
    uint32_t tsc_khz;
    uint32_t apic_khz;
    uint8_t standard_ioapic;
    uint8_t cpu_ids[255];
  } __attribute__((packed)) v1;
  struct {
    uint32_t flags;
  } __attribute__((packed)) v2;
} __attribute__((packed));

struct ima_setup_data {
  uint64_t addr;
  uint64_t size;
} __attribute__((packed));

struct boot_params {
  struct screen_info screen_info;                       /* 0x000 */
  struct apm_bios_info apm_bios_info;                   /* 0x040 */
  uint8_t _pad2[4];                                     /* 0x054 */
  uint64_t tboot_addr;                                  /* 0x058 */
  struct ist_info ist_info;                             /* 0x060 */
  uint64_t acpi_rsdp_addr;                              /* 0x070 */
  uint8_t _pad3[8];                                     /* 0x078 */
  uint8_t hd0_info[16]; /* obsolete! */                 /* 0x080 */
  uint8_t hd1_info[16]; /* obsolete! */                 /* 0x090 */
  struct sys_desc_table sys_desc_table; /* obsolete! */ /* 0x0a0 */
  struct olpc_ofw_header olpc_ofw_header;               /* 0x0b0 */
  uint32_t ext_ramdisk_image;                           /* 0x0c0 */
  uint32_t ext_ramdisk_size;                            /* 0x0c4 */
  uint32_t ext_cmd_line_ptr;                            /* 0x0c8 */
  uint8_t _pad4[112];                                   /* 0x0cc */
  uint32_t cc_blob_address;                             /* 0x13c */
  struct edid_info edid_info;                           /* 0x140 */
  struct efi_info efi_info;                             /* 0x1c0 */
  uint32_t alt_mem_k;                                   /* 0x1e0 */
  uint32_t scratch; /* Scratch field! */                /* 0x1e4 */
  uint8_t e820_entries;                                 /* 0x1e8 */
  uint8_t eddbuf_entries;                               /* 0x1e9 */
  uint8_t edd_mbr_sig_buf_entries;                      /* 0x1ea */
  uint8_t kbd_status;                                   /* 0x1eb */
  uint8_t secure_boot;                                  /* 0x1ec */
  uint8_t _pad5[2];                                     /* 0x1ed */
  uint8_t sentinel;                                     /* 0x1ef */
  uint8_t _pad6[1];                                     /* 0x1f0 */
  struct setup_header hdr; /* setup header */           /* 0x1f1 */
  uint8_t _pad7[0x290 - 0x1f1 - sizeof(struct setup_header)];
  uint32_t edd_mbr_sig_buffer[EDD_MBR_SIG_MAX];                 /* 0x290 */
  struct boot_e820_entry e820_table[E820_MAX_ENTRIES_ZEROPAGE]; /* 0x2d0 */
  uint8_t _pad8[48];                                            /* 0xcd0 */
  struct edd_info eddbuf[EDDMAXNR];                             /* 0xd00 */
  uint8_t _pad9[276];                                           /* 0xeec */
} __attribute__((packed));

enum x86_hardware_subarch {
  X86_SUBARCH_PC = 0,
  X86_SUBARCH_LGUEST,
  X86_SUBARCH_XEN,
  X86_SUBARCH_INTEL_MID,
  X86_SUBARCH_CE4100,
  X86_NR_SUBARCHS,
};

#endif // ASM_X86_BOOTPARAM_HPP_