#!/usr/bin/python3
from binascii import hexlify
import struct
import keystone
import capstone
import icdiff
import difflib
from xiaotea import XiaoTea

# https://web.eecs.umich.edu/~prabal/teaching/eecs373-f10/readings/ARMv7-M_ARM.pdf
MOVW_T3_IMM = [*[None]*5, 11, *[None]*6, 15, 14, 13, 12, None, 10, 9, 8, *[None]*4, 7, 6, 5, 4, 3, 2, 1, 0]
MOVS_T1_IMM = [*[None]*8, 7, 6, 5, 4, 3, 2, 1, 0]

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


class FirmwarePatcher():
    def __init__(self, data):
        self.data = bytearray(data)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_THUMB)
        self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)

    def encrypt(self):
        cry = XiaoTea()
        self.data = cry.encrypt(self.data)

    def disasm(self, bytes, ofs = 0x1000):
        asm = self.cs.disasm(bytes, ofs)
        return ["%08x %-08s\t%s\t%s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str) for i in asm]

    def debug(self, patch_name, patches):
        print(patch_name)
        print("-" * len(patch_name))
        for patch in patches:
            ofs, pre, post = patch
            d = icdiff.ConsoleDiff(cols=140)
            print("\r\n".join(d.make_table(self.disasm(pre, ofs), self.disasm(post, ofs))))
            print("\r\n")
        print("\r\n")

    def kers_min_speed(self, kmh):
        val = struct.pack('<H', int(kmh * 345))
        sig = [0x25, 0x68, 0x40, 0xF6, 0x16, 0x07, 0xBD, 0x42]
        ofs = FindPattern(self.data, sig) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        return [(ofs, pre, post)]

    # Normal: 28km/h (0x1c), 32000mA (0x7D00) / 17000mA (0x4268)
    # Eco: 22km/h (0x16), 17000mA (0x4268) / 7000mA (0x1B58)
    # 31, 50000, 30000, 26, 40000, 20000
    def speed_params(self, normal_kmh, normal_phase, normal_battery, eco_kmh, eco_phase, eco_battery):
        ret = []
        # 00006a54 8028                   cmp        r0, #0x80                            ; CODE XREF=sub_6998+182
        # 00006a56 00DD                   ble        loc_6a5a
        # 00006a58 8020                   movs       r0, #0x80                         ; CODE XREF=sub_6998+162
        # 00006a5a **
        # 00006a5c 6843                   muls       r0, r5, r0 -> MOVW R2
        # 00006a5e 000C                   lsrs       r0, r0, #0x10
        sig = [0x80, 0x28, 0x00, 0xDD, 0x80, 0x20, *[None]*2, 0x68, 0x43, 0x00, 0x0C]
        ofs = FindPattern(self.data, sig) + 8
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOVW R2, #{:n}'.format(normal_battery))[0])
        self.data[ofs:ofs+4] = post
        ret.append([ofs, pre, post])

        # 00006a60 E085                   strh       r0, [r4, #0x2e]
        ofs += 4
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('B #0x2A')[0])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])
        ofs += 2

        # 00006ada 012A                   cmp        r2, #0x1
        # 00006adc 44F26821               movw       r1, #0x4268
        # 00006ae0 4246                   mov        r2, r8
        # 00006ae2 05D0                   beq        loc_6af0
        sig = [0x01, 0x2A, 0x44, 0xF2, 0x68, 0x21, 0x42, 0x46, 0x05, 0xD0]
        ofs = FindPattern(self.data, sig) + 2
        pre, post = PatchImm(self.data, ofs, 4, struct.pack('<H', eco_phase), MOVW_T3_IMM)
        ret.append([ofs, pre, post])
        ofs += 4

        ofs += 10
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])
        ofs += 2

        ofs += 8
        pre, post = PatchImm(self.data, ofs, 4, struct.pack('<H', eco_battery), MOVW_T3_IMM)
        ret.append([ofs, pre, post])
        ofs += 4

        ofs += 2
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('B #0x06')[0])
        self.data[ofs:ofs+2] = post
        ret.append([ofs, pre, post])
        ofs += 2

        ofs += 6
        pre, post = PatchImm(self.data, ofs, 2, struct.pack('<B', eco_kmh), MOVS_T1_IMM)
        ret.append([ofs, pre, post])
        ofs += 2

        ofs += 6
        pre, post = PatchImm(self.data, ofs, 2, struct.pack('<B', normal_kmh), MOVS_T1_IMM)
        ret.append([ofs, pre, post])
        ofs += 2

        ofs += 2
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOVW R1, #{:n}'.format(normal_phase))[0])
        self.data[ofs:ofs+4] = post
        ret.append([ofs, pre, post])

        return ret

    # limit: 1 - 130, min: 0 - 65k, max: min - 65k
    def brake_params(self, limit, min, max):
        ret = []
        limit = int(limit)
        assert limit >= 1 and limit <= 130
        min = int(min)
        assert min >= 0 and min < 65536
        max = int(max)
        assert max >= min and max < 65536

        sig = [0x73, 0x29, 0x00, 0xDD, 0x73, 0x21, 0x45, 0xF2, 0xF0, 0x53, 0x59, 0x43, 0x73, 0x23, 0x91, 0xFB, 0xF3, 0xF1, None, 0x6C, 0x51, 0x1A, 0xA1, 0xF5, 0xFA, 0x51]
        ofs = FindPattern(self.data, sig)

        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('CMP R1, #{:n}'.format(limit))[0])
        self.data[ofs:ofs+2] = post
        ret.append((ofs, pre, post))
        ofs += 2

        ofs += 2
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('MOVS R1, #{:n}'.format(limit))[0])
        self.data[ofs:ofs+2] = post
        ret.append((ofs, pre, post))
        ofs += 2

        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOVW R3, #{:n}'.format(max - min))[0])
        self.data[ofs:ofs+4] = post
        ret.append((ofs, pre, post))
        ofs += 4

        ofs += 2
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('MOVS R3, #{:n}'.format(limit))[0])
        self.data[ofs:ofs+2] = post
        ret.append((ofs, pre, post))
        ofs += 2

        ofs += 8
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('SUB.W R1, R1, #{:n}'.format(min & 0xFF00))[0])
        self.data[ofs:ofs+4] = post
        ret.append((ofs, pre, post))

        return ret

    def voltage_limit(self, volts):
        val = struct.pack('<H', int(volts * 100) - 2600)
        sig = [0x40, 0xF2, 0xA5, 0x61, 0xA0, 0xF6, 0x28, 0x20, 0x88, 0x42]
        ofs = FindPattern(self.data, sig)
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        return [(ofs, pre, post)]

    def motor_start_speed(self, kmh):
        val = struct.pack('<H', int(kmh * 345))
        sig = [0xF0, 0xB4, None, 0x4C, 0x26, 0x68, 0x40, 0xF2, 0xBD, 0x67]
        ofs = FindPattern(self.data, sig) + 6
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        return [(ofs, pre, post)]

    # lower value = more power
    # original = 51575 (~500 Watt)
    # DYoC = 40165 (~650 Watt)
    # CFW W = 27877 (~850 Watt)
    # CFW = 25787 (~1000 Watt)
    def motor_power_constant(self, val):
        val = struct.pack('<H', int(val))
        ret = []
        sig = [0x31, 0x68, 0x2A, 0x68, 0x09, 0xB2, 0x09, 0x1B, 0x12, 0xB2, 0xD3, 0x1A, 0x4C, 0xF6, 0x77, 0x12]
        ofs = FindPattern(self.data, sig) + 12
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))
        ofs += 4

        ofs += 4
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))

        sig = [0xD3, 0x1A, 0x4C, 0xF6, 0x77, 0x12]
        ofs = FindPattern(self.data, sig, None, ofs, 100) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))
        ofs += 4

        ofs += 4
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))

        sig = [0xC9, 0x1B, 0x4C, 0xF6, 0x77, 0x13]
        ofs = FindPattern(self.data, sig, None, ofs, 100) + 2
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        ret.append((ofs, pre, post))
        return ret

    def instant_eco_switch(self):
        ret = []
        sig = [0x2C, 0xF0, 0x02, 0x0C, 0x81, 0xF8, 0x00, 0xC0, 0x01, 0x2A, 0x0A, 0xD0]
        ofs = FindPattern(self.data, sig) + 8
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append((ofs, pre, post))
        ofs += 2

        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('B #0x18')[0])
        self.data[ofs:ofs+2] = post
        ret.append((ofs, pre, post))
        ofs += 2

        sig = [0x4C, 0xF0, 0x02, 0x0C, 0x81, 0xF8, 0x00, 0xC0, 0x01, 0x2A, 0x06, 0xD1, 0x2B, 0xB9]
        ofs = FindPattern(self.data, sig, None, ofs, 100) + 8
        pre = self.data[ofs:ofs+6]
        post = bytes(self.ks.asm('NOP;NOP;NOP')[0])
        self.data[ofs:ofs+6] = post
        ret.append((ofs, pre, post))
        ofs += 6

        sig = [0x85, 0xF8, 0x34, 0x60, 0x02, 0xE0, 0x0B, 0xB9]
        ofs = FindPattern(self.data, sig, None, ofs, 100) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append((ofs, pre, post))
        return ret

    def boot_with_eco(self):
        ret = []
        sig = [0xB4, 0xF8, 0xEA, 0x20, 0x01, 0x2A, 0x02, 0xD1, 0x00, 0xF8, 0x34, 0x1F, 0x01, 0x72]
        ofs = FindPattern(self.data, sig)
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('STRH.W R1, [R4, #0xEA]')[0])
        self.data[ofs:ofs+4] = post
        ret.append((ofs, pre, post))
        ofs += 4

        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('NOP;NOP')[0])
        self.data[ofs:ofs+4] = post
        ret.append((ofs, pre, post))
        return ret

    def cruise_control_delay(self, delay):
        delay = int(delay * 200)
        assert delay.bit_length() <= 12, 'bit length overflow'
        sig = [0x35, 0x48, 0xB0, 0xF8, 0xF8, 0x10, 0x34, 0x4B, 0x4F, 0xF4, 0x7A, 0x70, 0x01, 0x29]
        mask= [0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        ofs = FindPattern(self.data, sig, mask) + 8
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOV.W R0, #{:n}'.format(delay))[0])
        self.data[ofs:ofs+4] = post
        return [(ofs, pre, post)]

    def cruise_control_nobeep(self):
        sig = [0xA8, 0xF8, None, 0x40, 0x88, 0xF8, 0x07, 0x60, 0x88, 0xF8, 0x10, 0x60, 0x28, 0x78, 0x88, 0xF8, 0x11, 0x00, 0x02, 0x20]
        ofs = FindPattern(self.data, sig) + 22
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        return [(ofs, pre, post)]

    def remove_hard_speed_limit(self):
        sig = [0x08, 0x60, 0x08, 0x68, 0x42, 0xF6, 0xE0, 0x62, 0x90, 0x42, None, 0xDC, 0x08, 0x68, 0xD0, 0x42]
        ofs = FindPattern(self.data, sig) + 8
        pre = self.data[ofs:ofs+10]
        post = bytes(self.ks.asm('NOP;'*5)[0])
        self.data[ofs:ofs+10] = post
        return [(ofs, pre, post)]

    def remove_charging_mode(self):
        sig = [0x19, 0xE0, None, 0xF8, 0x12, 0x00, 0x20, 0xB1, 0x84, 0xF8, 0x3A, 0x50, 0xE0, 0x7B, 0x18, 0xB1, 0x07, 0xE0]
        ofs = FindPattern(self.data, sig) + 6
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        return [(ofs, pre, post)]

    def stay_on_locked(self):
        sig = [None, 0x49, 0x40, 0x1C, *[None]*2, 0x88, 0x42, 0x03, 0xDB, *[None]*2, 0x08, 0xB9]
        ofs = FindPattern(self.data, sig) + 14
        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('NOP;NOP')[0])
        self.data[ofs:ofs+4] = post
        return [(ofs, pre, post)]

    def bms_uart_76800(self):
        ofs = 0
        while True:
            sig = [0x00, 0x21, 0x4F, 0xF4, 0xE1, 0x30, 0x00, 0x90, 0xAD, 0xF8, 0x08, 0x10, 0x0C, 0x20, 0xAD, 0xF8, 0x04, 0x10, 0xAD, 0xF8, 0x0A, 0x00, 0xAD, 0xF8, 0x06, 0x10]
            ofs = FindPattern(self.data, sig, None, ofs) + 2

            # USART3 address
            sig = [0x00, 0x48, 0x00, 0x40]
            try:
                FindPattern(self.data, sig, None, ofs, 0x100)
                break
            except SignatureException:
                continue

        pre = self.data[ofs:ofs+4]
        post = bytes(self.ks.asm('MOV.W R0, #76800')[0])
        self.data[ofs:ofs+4] = post
        return [(ofs, pre, post)]

    def wheel_speed_const(self, val):
        val = struct.pack('<H', int(val))
        sig = [0xB4, 0xF9, 0x1E, 0x00, 0x40, 0xF2, 0x59, 0x11, 0x48, 0x43]
        ofs = FindPattern(self.data, sig) + 4
        pre, post = PatchImm(self.data, ofs, 4, val, MOVW_T3_IMM)
        self.data[ofs:ofs+4] = post
        return [(ofs, pre, post)]

    def russian_throttle(self):
        ret = [dict()]
        # Find address of eco mode, part 1 find base addr
        sig = [0x91, 0x42, 0x01, 0xD2, 0x08, 0x46, 0x00, 0xE0, 0x10, 0x46, 0xA6, 0x4D]
        mask= [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF]
        ofs = FindPattern(self.data, sig, mask)
        ofs += 10
        imm = struct.unpack('<H', self.data[ofs:ofs + 2])[0] & 0xFF
        ofsa = ofs + imm * 4 + 4 # ZeroExtend '00' + align?
        eco_addr = struct.unpack('<L', self.data[ofsa:ofsa + 4])[0]

        ret[0]['eco_base'] = {'ofs': ofs, 'imm': imm, 'ofsa': ofsa, 'addr': hex(eco_addr)}

        # part 2, find offset of base addr
        sig = [0x85, 0xF8, 0x34, 0x60] # STRB.W  R6, [R5, #imm12]
        mask= [0xFF, 0xFF, 0x00, 0x0F] # mask imm12
        ofs = FindPattern(self.data, sig, mask, ofs, 100)
        imm = struct.unpack('<HH', self.data[ofs:ofs + 4])[1] & 0x0FFF
        eco_addr += imm

        ret[0]['eco_addr'] = {'ofs': ofs, 'imm': imm, 'addr': hex(eco_addr)}

        sig = [0xF0, 0xB5, 0x25, 0x4A, 0x00, 0x24, 0xA2, 0xF8, 0xEC, 0x40, 0x24, 0x49, 0x4B, 0x79, 0x00, 0x2B,
               0x3E, 0xD1, 0x23, 0x4D, 0x2F, 0x68, 0x23, 0x4E, 0x23, 0x4B, 0x00, 0x2F, 0x39, 0xDB, None, 0x64,
               0x01, 0x24, 0x74, 0x82, 0x32, 0x38, 0x01, 0xD5, 0x00, 0x20, 0x02, 0xE0, 0x7D, 0x28, 0x00, 0xDD,
               0x7D, 0x20, 0xB2, 0xF8, 0xEC, 0x60, 0x7D, 0x24, 0x26, 0xB1, 0xB2, 0xF8, 0xEC, 0x20, 0x01, 0x2A,
               0x0B, 0xD0, 0x13, 0xE0, 0xD1, 0xE9, None, 0x21, 0x52, 0x1A, 0x42, 0x43, 0x92, 0xFB, 0xF4, 0xF0,
               0x08, 0x44, 0x29, 0x68, 0x02, 0xF0, None, None, 0x08, 0xE0, 0x4A, 0x8C, 0x89, 0x8C, 0x52, 0x1A,
               0x42, 0x43, 0x92, 0xFB, 0xF4, 0xF0, 0x40, 0x18, 0x00, 0xD5, 0x00, 0x20, 0x19, 0x68, 0x09, 0x1A,
               0x19, 0x68, 0x01, 0xD5, 0x41, 0x1A, 0x00, 0xE0, 0x09, 0x1A, 0x4F, 0xF4, 0x96, 0x72, 0x91, 0x42,
               0x05, 0xDD, 0x19, 0x68, 0x81, 0x42, 0x00, 0xDD, 0x52, 0x42, 0x18, 0x68, 0x10, 0x44, 0x18, 0x60,
               0xF0, 0xBD, 0x1C, 0x60, 0x74, 0x82, 0xF0, 0xBD, *[None] * 4 * 5]
        ofs = FindPattern(self.data, sig)

        ofsa = ofs + len(sig) - (4 * 5)
        addr1, addr2, addr3, addr4, addr5 = struct.unpack('<LLLLL', self.data[ofsa:ofsa + 20])

        # STRH.W (T2)  Rt, [Rn, #imm12]
        addr1_ofs1 = struct.unpack('<H', self.data[ofs + 6 + 2:ofs + 6 + 2 + 2])[0] & 0xFFF

        # LDRB (T1)  Rt, [Rn, #imm5]
        addr2_ofs1 = (struct.unpack('<H', self.data[ofs + 12:ofs + 12 + 2])[0] >> 6) & 0x1F

        # STR (T1)  Rt, [Rn, #imm5]
        addr2_ofs2 = (struct.unpack('<H', self.data[ofs + 30:ofs + 30 + 2])[0] >> 6) & 0x1F
        addr2_ofs2 *= 4 # ZeroExtend '00'

        # STRH (T1)  Rt, [Rn, #imm5]
        addr4_ofs1 = (struct.unpack('<H', self.data[ofs + 34:ofs + 34 + 2])[0] >> 6) & 0x1F
        addr4_ofs1 *= 2 # ZeroExtend '0'

        ret[0]['addrs'] = {
                        '1': [hex(addr1), hex(addr1 + addr1_ofs1)],
                        '2': [hex(addr2), hex(addr2 + addr2_ofs1), hex(addr2 + addr2_ofs2)],
                        '3': [hex(addr3)],
                        '4': [hex(addr4), hex(addr4 + addr4_ofs1)],
                        '5': [hex(addr5)]
                        }

        asm = f'''
                LDR    R3, ={hex(addr2 + addr2_ofs1)}
                LDRB   R3, [R3]
                CBNZ   R3, loc_ret
                AND    R2, R3, #0xFF
                LDR    R3, ={hex(addr3)}
                LDR    R1, [R3]
                CMP    R1, #0
                BLT    loc_1
                PUSH   {{R4, R5}}
                LDR    R1, ={hex(addr4 + addr4_ofs1)}
                LDR    R5, ={hex(addr2 + addr2_ofs2)}
                MOVS   R4, #1
                SUBS   R0, #0x32
                STR    R2, [R5]
                STRH   R4, [R1]
                BMI    loc_3
                LDR    R2, ={hex(eco_addr)}
                CMP    R0, #0x7D
                LDRB   R2, [R2]
                IT     GE
                MOVGE  R0, #0x7D
                CMP    R2, R4
                BEQ    loc_2
                MOVS   R3, #0x96
                MUL    R3, R3, R0
                LDR    R2, ={hex(addr5)}
                STR    R3, [R2]

                loc_popret:
                POP    {{R4, R5}}

                loc_ret:
                BX     LR

                loc_1:
                LDR    R1, ={hex(addr5)}
                ADD.W  R3, R3, #0x1580
                ADDS   R3, #0x12
                STR    R2, [R1]
                STRH   R2, [R3]
                BX     LR

                loc_2:
                MOVW   R4, #0x1AF4
                MOVS   R2, #0x64
                MUL    R2, R2, R0
                LDR    R1, ={hex(addr5)}
                STR    R2, [R1]
                LDR    R2, [R3]
                CMP    R2, R4
                BLE    loc_popret
                LDR    R3, [R3]
                LDR    R2, [R1]
                SUB.W  R3, R3, #0x1AE0
                SUBS   R3, #0x14
                ADD.W  R3, R3, R3, LSL#2
                SUB.W  R3, R2, R3, LSL#1
                STR    R3, [R1]
                B      loc_popret

                loc_3:
                LDR    R3, ={hex(addr5)}
                MVN    R2, #0x9
                STR    R2, [R3]
                B      loc_popret
        '''

        res = self.ks.asm(asm)
        assert len(res[0]) <= len(sig), 'new code larger than old code, this won\'t work'
        assert len(res[0]) == 164, 'hardcoded size safety check, if you haven\'t changed the ASM then something is wrong'

        # pad with zero for no apparent reason
        padded = bytes(res[0]).ljust(len(sig), b'\x00')

        ret[0]['len_sig'] = len(sig)
        ret[0]['len_res'] = len(res[0])
        ret[0]['res_inst'] = res[1]

        self.data[ofs:ofs+len(padded)] = bytes(padded)

        # additional russian change
        sig = [0x07, 0xD0, 0x0B, 0xE0, 0x00, 0xEB, 0x40, 0x00, 0x40, 0x00, 0x05, 0xE0]
        mask= [0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        ofs = FindPattern(self.data, sig, mask) + 8
        pre = self.data[ofs:ofs+2]
        post = bytes(self.ks.asm('NOP')[0])
        self.data[ofs:ofs+2] = post
        ret.append((ofs, pre, post))

        return ret


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        eprint("Usage: {0} <orig-firmware.bin> <target.bin>".format(sys.argv[0]))
        exit(1)

    with open(sys.argv[1], 'rb') as fp:
        data = fp.read()

    cfw = FirmwarePatcher(data)

    # cfw.debug("kers_min_speed", cfw.kers_min_speed(45))
    cfw.debug("speed_params", cfw.speed_params(31, 50000, 30000, 26, 40000, 20000))
    # cfw.debug(cfw.brake_params(115, 8000, 50000))
    # cfw.debug(cfw.voltage_limit(52))
    # cfw.debug("motor_start_speed", cfw.motor_start_speed(3))
    # cfw.debug("instant_eco_switch", cfw.instant_eco_switch())
    #cfw.debug(cfw.boot_with_eco())
    #cfw.debug(cfw.cruise_control_delay(5))
    #cfw.debug(cfw.cruise_control_nobeep())
    # cfw.debug("remove_hard_speed_limit", cfw.remove_hard_speed_limit())
    #cfw.debug(cfw.remove_charging_mode())
    #cfw.debug(cfw.stay_on_locked())
    #cfw.debug(cfw.bms_uart_76800())
    #cfw.debug(cfw.russian_throttle())
    #cfw.debug(cfw.wheel_speed_const(315))
