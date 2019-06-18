#!/usr/bin/python3
from binascii import hexlify
import struct
import keystone
import capstone
import icdiff
import difflib
import io
import zipfile
import hashlib

from xiaotea import XiaoTea

# https://web.eecs.umich.edu/~prabal/teaching/eecs373-f10/readings/ARMv7-M_ARM.pdf
MOVW_T3_IMM = [*[None]*5, 11, *[None]*6, 15, 14, 13, 12, None, 10, 9, 8, *[None]*4, 7, 6, 5, 4, 3, 2, 1, 0]
MOVS_T1_IMM = [*[None]*8, 7, 6, 5, 4, 3, 2, 1, 0]

# https://scoding.de/ropper/
# https://github.com/fox-it/mkYARA/blob/master/mkyara/gen.py

def PatchImm(data, ofs, size, imm, signature):
    assert size % 2 == 0, 'size must be power of 2!'
    assert len(signature) == size * 8, 'signature must be exactly size * 8 long!'
    imm = int.from_bytes(imm, 'little')
    sfmt = '<' + 'H' * (size // 2)

    sigs = [signature[i:i + 16][::-1] for i in range(0, len(signature), 16)]
    orig = data[ofs:ofs+size]
    words = struct.unpack(sfmt, orig)
    patched = []
    for i, word in enumerate(words):
        for j in range(16):
            imm_bitofs = sigs[i][j]
            if imm_bitofs is None:
                continue

            imm_mask = 1 << imm_bitofs
            word_mask = 1 << j

            if imm & imm_mask:
                word |= word_mask
            else:
                word &= ~word_mask
        patched.append(word)
    packed = struct.pack(sfmt, *patched)
    data[ofs:ofs+size] = packed
    return (orig, packed)

class SignatureException(Exception):
    pass

def FindPattern(data, signature, mask=None, start=None, maxit=None):
    sig_len = len(signature)
    if start is None:
        start = 0
    stop = len(data) - len(signature)
    if maxit is not None:
        stop = start + maxit

    if mask:
        assert sig_len == len(mask), 'mask must be as long as the signature!'
        for i in range(sig_len):
            signature[i] &= mask[i]

    for i in range(start, stop):
        matches = 0

        while signature[matches] is None or signature[matches] == (data[i + matches] & (mask[matches] if mask else 0xFF)):
            matches += 1
            if matches == sig_len:
                return i

    raise SignatureException('Pattern not found!')

# 0x159 = 345 X to KM/H
# 0x57e4 HARD_LIMIT  ~65
# 0x20000238 = current speed
# 0x20000004 ???
# 0x2000070a = IS_SPORT_MODE???
# 0x20000706
# 0x2000023c

# 0x4268 = ECO PHASE
# 0x84d000 = BATTERY PHASE NORMAL

# SPEED LIMIT
# 0x200003f2 = 0x22; 34
# 0x200003f2 = 0x1c; 28 # sport  26-29
# 0x200003f2 = 0x16; 22 # normal 21-22
# 0x200003f2 = 0xc;  12 # eco 16-17
# 0x200003f2 = 0x5;   5

# PHASE CURRENT
# 0x200003fe = 0x61a8; 55000 # sport √
# 0x200003fe = 0x7D00; 32000 # drive
# 0x200003fe = 0x61a8; 25000
# 0x200003fe = 0x4268; 17000 # eco
# 0x200003fe = 0x2ee0; 12000
# 0x200003fe = 0x1b58;  7000
# 0x200003fe = 0xfa0;   4000
# 0x200003fe = 0x1f4;    500

# BATTERY CURRENT
# 0x200003f6 = 0x61A8; 25000 # sport
# 0x200003f6 = 0x4268; 17000 # drive
# 0x200003f6 = 0x1B58;  7000 # eco
# 0x200003f6 = 0x1388;  5000
# 0x200003f6 = 0x1f4;    500

# current??
# 0x20000424 = 0x61a8; 25000
# 0x20000424 = 0x1770;  6000
# 0x20000424 = 0x1f4;    500

# kers?
# if (*0x20000238 <= 0x40b) goto loc_1a30; 1035 / 345 = 3 km/h?
# if (*0x20000238 <= 0x190) goto loc_1a60; 400 / 345
# if (*0x20000238 <= 0x816) goto loc_19a8; 2070 / 345 = 6  = 3 km/h?
# if (*0x20000238 <= 0x190) goto loc_19e2; 400 / 345 = 1,159420289855072


class FirmwarePatcher():
    def __init__(self, data):
        self.data = bytearray(data)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_THUMB)
        self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)

    def encrypt(self):
        cry = XiaoTea()
        self.data = cry.encrypt(self.data)

    def disasm(self, bytes, ofs):
        asm = self.cs.disasm(bytes, 0x08001000 + ofs)
        return ["%08x %-08s\t%s\t%s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str) for i in asm]

    def debug(self, patch_name, patches):
        print(patch_name)
        print("-" * len(patch_name))
        for patch in patches:
            ofs, pre, post = patch
            d = icdiff.ConsoleDiff(cols=140)
            print("\r\n".join(d.make_table(self.disasm(pre, ofs), self.disasm(post, ofs))))
        print("\r\n")

    # Stock: 6km/h (0x816 / 345)
    def kers_min_speed(self, kmh):
        # 0000196a 2668                   ldr        r6, [r4]                             ; CODE XREF=sub_1928+38
        # 0000196c 40F6160C               movw       ip, #2070                            ; 2070 / 345 = 6km/h
        # 00001970 6645                   cmp        r6, ip
        sig = [0x26, 0x68, 0x40, 0xF6, 0x16, 0x0C, 0x66, 0x45]
        val = struct.pack('<H', int(kmh * 345))
        ofs = FindPattern(self.data, sig) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        return [(ofs, pre, post)]

    # Stock: 5km/h (0x6bd/345)
    def motor_start_speed(self, kmh):
        # 00006ee4 F0B4                   push       {r4, r5, r6, r7}                     ; CODE XREF=sub_743c+2
        # 00006ee6 234C                   ldr        r4, =0x20000238                      ; dword_6f74
        # 00006ee8 2668                   ldr        r6, [r4]
        # 00006eea 40F2BD67               movw       r7, #0x6bd
        sig = [0xF0, 0xB4, None, 0x4C, 0x26, 0x68, 0x40, 0xF2, 0xBD, 0x67]
        val = struct.pack('<H', int(kmh * 345))
        ofs = FindPattern(self.data, sig) + 6
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        return [(ofs, pre, post)]

    # lower value = more power
    # original = 51575 (~500 Watt)
    # DYoC = 40165 (~650 Watt)
    # CFW W = 27877 (~850 Watt)
    # CFW = 25787 (~1000 Watt)
    # NOTE: Looks like this is dead code, nothing references here
    def motor_power_constant(self, val):
        ret = []
        # 000050fa 3168                   ldr        r1, [r6]                             ; case 6, CODE XREF=sub_50d4+26
        # 000050fc 2A68                   ldr        r2, [r5]
        # 000050fe 09B2                   sxth       r1, r1
        # 00005100 091B                   subs       r1, r1, r4
        # 00005102 12B2                   sxth       r2, r2
        # 00005104 D31A                   subs       r3, r2, r3
        # 00005106 4CF67712               movw       r2, #0xc977
        val = struct.pack('<H', int(val))
        sig = [0x31, 0x68, 0x2A, 0x68, 0x09, 0xB2, 0x09, 0x1B, 0x12, 0xB2, 0xD3, 0x1A, 0x4C, 0xF6, 0x77, 0x12]
        ofs = FindPattern(self.data, sig) + 12
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))

        # 0000510a 5143                   muls       r1, r2, r1
        # 0000510c 8A12                   asrs       r2, r1, #0xa
        # 0000510e 4CF67711               movw       r1, #0xc977
        ofs += 8
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))

        # 00005124 D31A                   subs       r3, r2, r3
        # 00005126 4CF67712               movw       r2, #0xc977
        # 0000512a 5143                   muls       r1, r2, r1
        # 0000512c 8A12                   asrs       r2, r1, #0xa
        sig = [0xD3, 0x1A, 0x4C, 0xF6, 0x77, 0x12]
        ofs = FindPattern(self.data, sig, None, ofs, 100) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))

        # 0000512e 4CF67711               movw       r1, #0xc977
        # 00005132 4B43                   muls       r3, r1, r3
        # 00005134 5142                   rsbs       r1, r2, #0x0
        # 00005136 02EBA322               add.w      r2, r2, r3, asr #10
        ofs += 8
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))

        # 00005142 C91B                   subs       r1, r1, r7
        # 00005144 4CF67713               movw       r3, #0xc977
        sig = [0xC9, 0x1B, 0x4C, 0xF6, 0x77, 0x13]
        ofs = FindPattern(self.data, sig, None, ofs, 100) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))
        return ret


    # 00005a5c 6843           muls    r0, r5, r0                            00005a5c 47f23052       movw    r2, #0x7530
    # 00005a5e 000c           lsrs    r0, r0, #0x10
    # 00005a60 e085           strh    r0, [r4, #0x2e]                       00005a60 13e0           b       #0x5a8a
    # 00005adc 44f26821       movw    r1, #0x4268                           00005adc 49f64041       movw    r1, #0x9c40
    # 00005aea 0dd2           bhs     #0x5b08                               00005aea 00bf           nop
    # 00005af4 41f65832       movw    r2, #0x1b58                           00005af4 44f62062       movw    r2, #0x4e20
    # 00005afa 01d2           bhs     #0x5b00                               00005afa 01e0           b       #0x5b00
    # 00005b02 1622           movs    r2, #0x16                             00005b02 1a22           movs    r2, #0x1a
    # 00005b0a 1c21           movs    r1, #0x1c                             00005b0a 1f21           movs    r1, #0x1f
    # 00005b0e 4ff4fa41       mov.w   r1, #0x7d00                           00005b0e 4cf25031       movw    r1, #0xc350
    def speed_params(self, sport_kmh, sport_phase, sport_battery, normal_kmh, normal_phase, normal_battery, eco_kmh, eco_phase, eco_battery):
        ret = []
        # 00006a88 5043                   muls       r0, r2, r0                           ; CODE XREF=sub_69dc+168
        # 00006a8a 000C                   lsrs       r0, r0, #0x10
        # 00006a8c E085                   strh       r0, [r4, #0x2e]
        # 00006a8e D548                   ldr        r0, =0x2000091c                      ; dword_6de4
        # 00006a90 B0F96200               ldrsh.w    r0, [r0, #0x62]
        # 00006a94 B0F5617F               cmp.w      r0, #0x384
        # 00006a98 0DDA                   bge        loc_6ab6
        sig = [0x50, 0x43, 0x00, 0x0C, 0xE0, 0x85, 0xD5, 0x48, 0xB0, 0xF9, 0x62, 0x00, 0xB0, 0xF5, 0x61, 0x7F, 0x0D, 0xDA]

        ofs = FindPattern(self.data, sig) + 0
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('movw r2, #{:n}'.format(normal_battery))[0])
        self.data[ofs:ofs+4] = post
        ret.append([ofs, pre, post])


        # 00006a60 E085                   strh       r0, [r4, #0x2e]
        ofs += 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('B #0x2A')[0]) # 42?
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])
        ofs += 2

        # 00006b22 41F6583E               movw       lr, #0x1b58
        # 00006b26 44F2682A               movw       sl, #0x4268
        sig = [0x41, 0xF6, 0x58, 0x3E, 0x44, 0xF2, 0x68, 0x2A]
        ofs = FindPattern(self.data, sig) + 4
        pre, post = PatchImm(self.data, ofs, 4, struct.pack('<H', eco_phase), MOVW_T3_IMM)
        ret.append([ofs, pre, post])


        # A1F8EA60               strh.w     r6, [r1, #0xea]
        # 5045                   cmp        r0, sl
        # 0BD2                   bhs        loc_6b90
        sig = [0xA1, 0xF8, 0xEA, 0x60, 0x50, 0x45, 0x0B, 0xD2]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])

        # pre, post = PatchImm(self.data, ofs, 4, struct.pack('<H', eco_battery), MOVW_T3_IMM)
        # ret.append([ofs, pre, post])
        # ofs += 4
        #
        # ofs += 2
        # pre = self.data[ofs:ofs+2]
        # post = bytes(self.ks.asm('B #0x06')[0])
        # self.data[ofs:ofs+2] = post
        # ret.append([ofs, pre, post])
        # ofs += 2
        #
        # ofs += 6
        # pre, post = PatchImm(self.data, ofs, 2, struct.pack('<B', eco_kmh), MOVS_T1_IMM)
        # ret.append([ofs, pre, post])
        # ofs += 2
        #
        # ofs += 6
        # pre, post = PatchImm(self.data, ofs, 2, struct.pack('<B', normal_kmh), MOVS_T1_IMM)
        # ret.append([ofs, pre, post])
        # ofs += 2
        #
        # ofs += 2
        # pre = self.data[ofs:ofs+4]
        # post = bytes(self.ks.asm('MOVW R1, #{:n}'.format(normal_phase))[0])
        # self.data[ofs:ofs+4] = post
        # ret.append([ofs, pre, post])

        return ret

    # Stock 1.3.8: ~35km/h (12000/345)
    # Stock 1.5.5: ~65km/h (22500/345)
    # 1.5.5 is already high enough, probably no longer needed
    def remove_hard_speed_limit(self):
        # 000068a4 0860                   str        r0, [r1]
        # 000068a6 0868                   ldr        r0, [r1]
        # 000068a8 45F2E472               movw       r2, #0x57e4
        # 000068ac 9042                   cmp        r0, r2
        # 000068ae 54DC                   bgt        loc_695a
        # 000068b0 0868                   ldr        r0, [r1]
        # 000068b2 D042                   cmn        r0, r2
        sig = [0x08, 0x60, 0x08, 0x68, 0x45, 0xF2, 0xE4, 0x72, 0x90, 0x42, None, 0xDC, 0x08, 0x68, 0xD0, 0x42]
        ofs = FindPattern(self.data, sig) + 8
        pre = self.data[ofs:ofs+10]
        post = bytes(self.ks.asm('NOP;'*5)[0])
        self.data[ofs:ofs+10] = post
        return [(ofs, pre, post)]

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        eprint("Usage: {0} <orig-firmware.bin> <target.zip>".format(sys.argv[0]))
        exit(1)

    with open(sys.argv[1], 'rb') as fp:
        data = fp.read()

    cfw = FirmwarePatcher(data)

    cfw.debug("kers_min_speed", cfw.kers_min_speed(45))

    # Stock PRO: 55000 / 25000 ~ 2,2
    # Stock M365: 32000 / 17000 ~ 1,882352941176471
    # 50000 / 26500 Rollerplausch.com ~ 1,886792452830189
    # 60000 / 30000 BotoX ~ 2
    # 41000 / 22000 DYoC ~ 2,05
    # cfw.debug("speed_params", cfw.speed_params(
    #     31, 41000, 22000,
    #     28, 32000, 17000,
    #     22, 17000, 7000
    #  ))

    # cfw.debug("motor_start_speed", cfw.motor_start_speed(2))
    # cfw.debug("motor_power_constant", cfw.motor_power_constant(27877))
    # cfw.debug("remove_hard_speed_limit", cfw.remove_hard_speed_limit())

    with open(sys.argv[2], 'wb') as fp:
        fp.write(cfw.data)

    # # make zip file for firmware
    # zip_buffer = io.BytesIO()
    # zip_file = zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False)
    #
    # zip_file.writestr('FIRM.bin', cfw.data)
    # md5 = hashlib.md5()
    # md5.update(cfw.data)
    #
    # cfw.encrypt()
    # zip_file.writestr('FIRM.bin.enc', cfw.data)
    # md5e = hashlib.md5()
    # md5e.update(cfw.data)
    #
    # info_txt = 'dev: M365;\nnam: {};\nenc: B;\ntyp: DRV;\nmd5: {};\nmd5e: {};\n'.format(
    #     "DRV155", md5.hexdigest(), md5e.hexdigest())
    #
    # zip_file.writestr('info.txt', info_txt.encode())
    # zip_file.close()
    # zip_buffer.seek(0)
    # content = zip_buffer.getvalue()
    # zip_buffer.close()
    #
    # with open(sys.argv[2], 'wb') as fp:
    #     fp.write(content)
