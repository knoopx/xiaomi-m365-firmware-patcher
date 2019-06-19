from idaapi import *
from idc import *
import os
import sys
import operator
import sqlite3

_FLASH_BASEADDR = 0x00018000
_FLASH_SIZE = 0x8000
_RAM_BASEADDR = 0x20002000
_RAM_SIZE = 0x2000
_BOUNDARY = 0x100

# nRF51822	Nordic Semiconductor	Cortex-M0 MCU with BLE

# The processor implements the ARMv6-M Thumb instruction set, including a number of 32-bit instructions that use Thumb-2 technology. The ARMv6-M instruction set comprises:
# * all of the 16-bit Thumb instructions from ARMv7-M excluding CBZ, CBNZ and IT
# * the 32-bit Thumb instructions BL, DMB, DSB, ISB, MRS and MSR.


# 318|s110|nrf51822|xxab|0x20002000|0x2000|0x18000|0x8000|10.0.0|26d6240e598f89b8aeabcecb96f3c5595b07bfc315b969a13aca34b2e61a7dc0


# 0xE000E100	ISER	RW	0x00000000	Interrupt Set-enable Register
# 0xE000E180	ICER	RW	0x00000000	Interrupt Clear-enable Register
# 0xE000E200	ISPR	RW	0x00000000	Interrupt Set-pending Register
# 0xE000E280	ICPR	RW	0x00000000	Interrupt Clear-pending Register
# 0xE000E400-0xE000E41C	IPR0-7	RW	0x00000000	Interrupt Priority Registers

# 0x40000000-0x40000FFF Timer0 -
# 0x40001000-0x40001FFF Timer1 -
# 0x40005000-0x40005FFF UART1
# 0x40006000-0x40006FFF UART2
# 0x40007000-0x40007FFF UART3
# 0x40009000-0x40009FFF UART4
# 0x40010000-0x40010FFF (4KB) CMSDK AHB GPIO #0
# 0x40011000-0x40011FFF (4KB) CMSDK AHB GPIO #1
# 0x4001F000-0x4001FFFF (4KB) System controller registers.
# 0xF0000000-0xF0000400 (4KB) System ROM table.

# 0x01000000-0x0100FFFF (64KB) Optional boot loader memory. Actual size 4KB, access above 4KB are aliased

# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0497a/BABIFJFG.html
# https://zhuanlan.zhihu.com/p/22048373
# https://github.com/stef/idapro-cortex-m-hwregs/blob/master/structs.h

_ANNOTATIONS = [
    "INITIAL_SP",
    "RESET",
    "NMI",
    "HARDFAULT",
    "RESERVED1", "RESERVED2", "RESERVED3", "RESERVED4", "RESERVED5", "RESERVED6", "RESERVED7",
    "SVC",
    "RESERVED8", "RESERVED9",
    "PENDSV",
    "SYSTICK",
    "POWER_CLOCK_IRQ",
    "RADIO_IRQ",
    "UART0_IRQ",
    "SPI0_TWI0_IRQ",
    "SPI1_TWI1_IRQ",
    "RESERVED10",
    "GPIOTE_IRQ",
    "ADC_IRQ",
    "TIMER0_IRQ",
    "TIMER1_IRQ",
    "TIMER2_IRQ",
    "RTC0_IRQ",
    "TEMP_IRQ",
    "RNG_IRQ",
    "ECB_IRQ",
    "CCM_AAR_IRQ",
    "WDT_IRQ",
    "RTC1_IRQ",
    "QDEC_IRQ",
    "LPCOMP_IRQ",
    "SWI0_IRQ", "SWI1_IRQ", "SWI2_IRQ", "SWI3_IRQ", "SWI4_IRQ", "SWI5_IRQ",
    "RESERVED11", "RESERVED12", "RESERVED13", "RESERVED14", "RESERVED15", "RESERVED16"
]

# This Walker implementation seems like overkill, but allows code to work on
# loader_input and segments as well.
class _Walker:
   def __init__(self, startaddress, endaddress):
      self.startaddress = startaddress
      self.endaddress = endaddress
      self.address = startaddress

   def skip(self, offset):
      self.address += offset

   def seek(self, offset):
      self.address = self.startaddress + offset

   def _valid(self):
      return self.address >= self.startaddress and self.address < self.endaddress

   def word(self):
      if not self._valid():
         return (None, None)
      return (self.address, self._word())

   def wordinc(self):
      result = self.word()
      self.address += 2
      return result

   def dword(self):
      if not self._valid():
         return (None, None)
      return (self.address, self._dword())

   def dwordinc(self):
      result = self.dword()
      self.address += 4
      return result

class MemoryWalker(_Walker):
   def __init__(self, startaddress, endaddress):
      _Walker.__init__(self, startaddress, endaddress)

   def _word(self):
      return Word(self.address)

   def _dword(self):
      return Dword(self.address)

class LoaderInputWalker(_Walker):
   def __init__(self, li):
      _Walker.__init__(self, 0, li.size())
      self.li = li

   def _read(self, bytes):
      self.li.seek(self.address)
      return self.li.read(bytes)

   def _word(self):
      return struct.unpack('<H', self._read(2))[0]

   def _dword(self):
      return struct.unpack('<I', self._read(4))[0]

# startaddress and endaddress are the valid range of Flash addresses
def estimate_vector_table_length(walker, startaddress, endaddress):
   'Returns estimated length of vector table'

   walker.skip(4) # skip stackpointer

   length = 1 # count skipped stackpointer
   while True:
      address, dword = walker.dwordinc()
      dword &= ~1 # clear LSB
      if address == None:
         break
      elif dword != 0 and (dword < startaddress or dword >= endaddress):
         break
      length += 1

   return length

_NULLSUB = 0x4770 # BX LR
_LOOPSUB = 0xe7fe # loop: B loop

def estimate_base_offset(walker, numentries):
   'Returns the best estimate for offset of base address'
   vector_table_length = list()
   subs = list()
   vals = dict()

   walker.skip(2 * 4) # skip stackpointer and entrypoint

   # generate list of vector table jump addresses
   for index in range(2, numentries):
      address, entry = walker.dwordinc()
      if entry == 0:
         continue
      entry &= ~1 # clear LSB
      vector_table_length.append(entry)

   # generate list of potential null- or loopsub addresses
   # nullsub detection finds lots of false positive
   while True:
      address, word = walker.wordinc()
      if address == None:
         break
      elif word == _NULLSUB or word == _LOOPSUB:
         subs.append(address)

   # generate frequency dictionary of offsets
   for entry in vector_table_length:
      for sub in subs:
         offset = entry - sub
         vals[offset] = vals.get(offset, 0) + 1

   sorted_vals = sorted(vals.iteritems(), key=operator.itemgetter(1), reverse=True)

   # loop best fits
   i = 0
   while i < len(sorted_vals):
      if sorted_vals[i][0] % _BOUNDARY == 0:
         msg('Taking estimate nr. %i\n' % (i + 1))
         return sorted_vals[i][0]
      i += 1

   return None

def analyze_vector_table(start, vector_table_length):
   msg("Analyzing %d vector table vector_table_length...\n" % vector_table_length)
   walker = MemoryWalker(start, start + (4 * vector_table_length))

   num = -1
   for index in range(1, vector_table_length):
      if _ANNOTATIONS[index:]:
        annotation = _ANNOTATIONS[index]
      else:
        num+=1
        annotation = "UNKNOWN%d" % num

      address, entry = walker.dwordinc()
      entry_name = "%s_%08x" % (annotation, address)
      idc.MakeDword(address)
      msg("Annotating 0x%08x as %s\n" % (address, annotation))
      ida_name.set_name(address, annotation, 0)

      # if entry == 0xe7fe:
      #    idc.SetFunctionCmt(address, 'Infinite Loop', 1)

      if entry == 0:
         continue
      else:
         entry &= ~1
         add_func(entry, BADADDR)
         idc.SetFunctionCmt(entry, annotation, 1)


def find_function_epilogue_bxlr(EAstart, EAend):
    '''
    Find opcode bytes corresponding to BX LR.
    This is a common way to return from a function call.
    Using the IDA API, convert these opcodes to code. This kicks off IDA analysis.
    '''
    ea = EAstart
    length = 2 # this code isn't tolerant to values other than 2 right now

    fmt_string = "Possible BX LR 0x%08x == "
    for i in range(length):
        fmt_string += "%02x "

    while ea < EAend:
        instructions = []
        for i in range(length):
            instructions.append(idc.Byte(ea + i))

        if not ida_bytes.isCode(ida_bytes.getFlags(ea)) and instructions[0] == 0x70 and instructions[1] == 0x47:
            print fmt_string % (ea, instructions[0], instructions[1])
            idc.MakeCode(ea)
        ea = ea + length


def find_pushpop_registers_thumb(EAstart, EAend):
    '''
    Look for opcodes that push registers onto the stack, which are indicators of function prologues.
    Using the IDA API, convert these opcodes to code. This kicks off IDA analysis.
    '''

    '''
    thumb register list from luis@ringzero.net
    '''

    thumb_reg_list = [0x00, 0x02, 0x08, 0x0b, 0x0e, 0x10, 0x1c, 0x1f, 0x30, 0x30, 0x38, 0x3e, 0x4e,
    0x55, 0x70, 0x72, 0x73, 0x7c, 0x7f, 0x80, 0x90, 0xb0, 0xf0, 0xf3, 0xf7, 0xf8, 0xfe, 0xff]

    ea = EAstart
    length = 2 # this code isn't tolerant to values other than 2 right now

    fmt_string = "Possible Function 0x%08x == "
    for i in range(length):
        fmt_string += "%02x "

    while ea < EAend:
        instructions = []
        for i in range(length):
            instructions.append(idc.Byte(ea + i))

        if not ida_bytes.isCode(ida_bytes.getFlags(ea)) and instructions[0] in thumb_reg_list and (instructions[1] == 0xb5 or instructions[1]== 0xbd):
            print fmt_string % (ea, instructions[0], instructions[1])
            idc.MakeCode(ea)
        ea = ea + length

def make_new_functions_heuristic_push_regs(EAstart, EAend):
    '''
    After converting bytes to instructions, Look for PUSH instructions that are likely the beginning of functions.
    Convert these code areas to functions.
    '''
    ea = EAstart

    while ea < EAend:
        ea_function_start = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)

        # If ea is inside a defined function, skip to end of function
        if ea_function_start != idc.BADADDR:
            ea = idc.FindFuncEnd(ea)
            continue

        # If current ea is code
        if ida_bytes.isCode(ida_bytes.getFlags(ea)):
            # Looking for prologues that do PUSH {register/s}
            mnem = idc.GetMnem(ea)

            #
            if (
                mnem == "PUSH"
            ):
                print "Converting code to function @ %08x" % ea
                idc.MakeFunction(ea)

                eanewfunction = idc.FindFuncEnd(ea)
                if eanewfunction != idc.BADADDR:
                    ea = eanewfunction
                    continue

        nextcode = ida_search.find_code(ea, idc.SEARCH_DOWN)

        if nextcode != idc.BADADDR:
            ea = nextcode
        else:
            ea += 1

def accept_file(li, filename):
   return 'Cortex M0'

def load_file(li, neflags, format):
   set_processor_type('ARM:ARMv6-M', SETPROC_ALL | SETPROC_FATAL)
   walker = LoaderInputWalker(li)
   vector_table_length = estimate_vector_table_length(walker, _FLASH_BASEADDR, _FLASH_BASEADDR + _FLASH_SIZE)
   # omitted: error handling
   msg('Estimated vector table length: %i \n' % vector_table_length)
   walker.seek(0)
   base_address = estimate_base_offset(walker, vector_table_length)
   msg('Estimated base address: 0x%08x \n' % base_address)


   add_entry(1, base_address, "entrypoint", 1)

   add_segm(0, _RAM_BASEADDR, _RAM_BASEADDR + _RAM_SIZE, 'RAM', None)
   add_segm(0, _FLASH_BASEADDR, _FLASH_BASEADDR + _FLASH_SIZE, 'FLASH', "CODE")

   add_segm(0, 0x40000000, 0x4000FFFF, 'CMSDK subsystem APB peripherals', None)
   add_segm(0, 0x40000000, 0x40000FFF, 'Timer0', None)
   add_segm(0, 0x40001000, 0x40001FFF, 'Timer1', None)

   add_segm(0, 0x40005000, 0x40005FFF, 'UART1', None)
   add_segm(0, 0x40006000, 0x40006FFF, 'UART2', None)
   add_segm(0, 0x40007000, 0x40007FFF, 'UART3', None)
   add_segm(0, 0x40009000, 0x40009FFF, 'UART4', None)

   # 0x40009000-0x40009FFF	UART4	-
   #  0x40008000-0x40008FFF	Watchdog	-
   #  0x40007000-0x40007FFF	UART3	-
   #  0x40006000-0x40006FFF	UART2
   #  0x40005000-0x40005FFF	UART1	-
   #  0x40004000-0x40004FFF	UART0

   add_segm(0, 0x40011000, 0x40011FFF, 'CMSDK AHB GPIO #1', None)
   add_segm(0, 0x40010000, 0x40010FFF, 'CMSDK AHB GPIO #0', None)

   SetRegEx(_FLASH_BASEADDR, 'T', 1, SR_user)
   li.file2base(0, base_address, base_address + li.size(), FILEREG_PATCHABLE)
   # add_hidden_area(_FLASH_BASEADDR, base_address, 'Unknown flash', '', '', DEFCOLOR)

   autoWait()
   ApplySig("armlibl")
   ApplySig("armlib_l")

   analyze_vector_table(base_address, vector_table_length)

   autoWait()

   find_function_epilogue_bxlr(base_address, _FLASH_BASEADDR + _FLASH_SIZE)
   find_pushpop_registers_thumb(base_address, _FLASH_BASEADDR + _FLASH_SIZE)
   make_new_functions_heuristic_push_regs(base_address, _FLASH_BASEADDR + _FLASH_SIZE)

   return 1
