from idaapi import *
from idc import *
import sys
import operator

# Only tested for Cortex-M3, little endian
# IDA uses nomenclature byte, word, dword, whereas ARM uses byte, half word, word

# Device dependent values
_FLASH_BASEADDR = 0x08000000
_FLASH_SIZE = 0x10000   # 64kb flash
_RAM_BASEADDR = 0x20000000
_RAM_SIZE = 0x5000 # 20kb ram
_BOUNDARY = 0x100

# 08000000	bootloader
# 08001000	app
# 08008400	update
# 0800F800	app_config
# 0800FC00	upd_config

# https://github.com/etransport/ninebot-docs/wiki/M365ESC

# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABIFJFG.html
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

   index = 1 # count skipped stackpointer
   while True:
      address, dword = walker.dwordinc()
      dword &= ~1 # clear LSB
      if address == None:
         break
      elif dword != 0 and (dword < startaddress or dword >= endaddress):
         break
      index += 1

   return index

_NULLSUB = 0x4770 # BX LR
_LOOPSUB = 0xe7fe # loop: B loop

def estimate_base_offset(walker, numentries):
   'Returns the best estimate for offset of base address'
   entries = list()
   subs = list()
   vals = dict()

   walker.skip(2 * 4) # skip stackpointer and entrypoint

   # generate list of vector table jump addresses
   for index in range(2, numentries):
      address, entry = walker.dwordinc()
      if entry == 0:
         continue
      entry &= ~1 # clear LSB
      entries.append(entry)

   # generate list of potential null- or loopsub addresses
   # nullsub detection finds lots of false positive
   while True:
      address, word = walker.wordinc()
      if address == None:
         break
      elif word == _NULLSUB or word == _LOOPSUB:
         subs.append(address)

   # generate frequency dictionary of offsets
   for entry in entries:
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

def analyze_vector_table(start, entries):
   walker = MemoryWalker(start, start + 4 * entries)

   # skip stackpointer
   walker.skip(4)

   # mark called functions for analysis
   for index in range(1, entries):
      address, entry = walker.dwordinc()
      if entry == 0:
         continue
      else:
         entry &= ~1
         add_func(entry, BADADDR)

   # make vector table an array
   doDwrd(start, 4 * entries)

# loader code

def accept_file(li, filename):
   return 'Cortex M3'

def load_file(li, neflags, format):
   set_processor_type('ARM:ARMv7-M', SETPROC_ALL | SETPROC_FATAL)
   walker = LoaderInputWalker(li)
   vector_table_length = estimate_vector_table_length(walker, _FLASH_BASEADDR, _FLASH_BASEADDR + _FLASH_SIZE)
   # omitted: error handling
   msg('Estimated vector table length: %i \n' % vector_table_length)
   walker.seek(0)
   base_address = estimate_base_offset(walker, vector_table_length)
   # omitted: error handling
   msg('Estimated base address: 0x%08x \n' % base_address)
   add_segm(0, _RAM_BASEADDR, _RAM_BASEADDR + _RAM_SIZE, 'RAM', None)
   add_segm(0, _FLASH_BASEADDR, _FLASH_BASEADDR + _FLASH_SIZE, 'FLASH', None)
   SetRegEx(_FLASH_BASEADDR, 'T', 1, SR_user)
   li.file2base(0, base_address, base_address + li.size(), FILEREG_PATCHABLE)
   add_hidden_area(_FLASH_BASEADDR, base_address, 'Unknown flash', '', '', DEFCOLOR)
   analyze_vector_table(base_address, vector_table_length)
   return 1
