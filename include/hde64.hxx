#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define F_ERROR 0x00001000

#pragma pack(push, 1)
struct hde64s {
    unsigned char len;
    unsigned char p_rep;
    unsigned char p_lock;
    unsigned char p_seg;
    unsigned char p_66;
    unsigned char p_67;
    unsigned char rex;
    unsigned char rex_w;
    unsigned char rex_r;
    unsigned char rex_x;
    unsigned char rex_b;
    unsigned char opcode;
    unsigned char opcode2;
    unsigned char modrm;
    unsigned char modrm_mod;
    unsigned char modrm_reg;
    unsigned char modrm_rm;
    unsigned char sib;
    unsigned char sib_scale;
    unsigned char sib_index;
    unsigned char sib_base;
    union {
        unsigned char imm8;
        unsigned short imm16;
        unsigned int imm32;
        unsigned long long imm64;
    } imm;
    union {
        unsigned char disp8;
        unsigned short disp16;
        unsigned int disp32;
    } disp;
    unsigned int flags;
};
#pragma pack(pop)

unsigned int hde64_disasm(const void* code, struct hde64s* hs);

#ifdef __cplusplus
}
#endif
