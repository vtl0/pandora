#ifndef ARCH_X86_HPP_
#define ARCH_X86_HPP_

#include <cstdint>

#define SIZE_OVERRIDE_MASK 0b11111110
#define OPERAND_SIZE_OVERRIDE 0b01100110
#define ADDRESS_SIZE_OVERRIDE 0b01100111
#define P_REX 0b01000000
#define P_IS_REX(x) (P_REX == (x & 0b11110000))
#define P_B_BIT 0b0001
#define P_X_BIT 0b0010
#define P_R_BIT 0b0100
#define P_W_BIT 0b1000
#define P_LOCK 0xF0
#define P_REPNZ 0xF2
#define P_REPZ 0xF3
#define P_ES 0x26
#define P_CS 0x2E
#define P_SS 0x36
#define P_DS 0x3E
#define P_FS 0x64
#define P_GS 0x65

#define CR0_PE (1ULL << 0)
#define CR0_MP (1ULL << 1)
#define CR0_EM (1ULL << 2)
#define CR0_TS (1ULL << 3)
#define CR0_ET (1ULL << 4)
#define CR0_NE (1ULL << 5)
#define CR0_WP (1ULL << 16)
#define CR0_AM (1ULL << 18)
#define CR0_NW (1ULL << 29)
#define CR0_CD (1ULL << 30)
#define CR0_PG (1ULL << 31)

#define CR4_LA57 (1ULL << 12)
#define CR4_CET (1ULL << 23)

#define IA32_MTRR_DEF_TYPE 0x2FF
#define MTRR_DEF_TYPE_E_ENABLE (1ULL << 11)
#define IA32_U_CET 0x6A0
#define IA32_S_CET 0x6A2

#endif // ARCH_X86_HPP_