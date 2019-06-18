import sys
import operator
import struct

_BOUNDARY = 0x100

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
      bytes = li.read()
      li.seek(0)
      _Walker.__init__(self, 0, len(bytes))
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

   sorted_vals = sorted(vals.items(), key=operator.itemgetter(1), reverse=True)

   # loop best fits
   i = 0
   while i < len(sorted_vals):
      if sorted_vals[i][0] % _BOUNDARY == 0:
         print('Taking estimate nr. %i\n' % (i + 1))
         return sorted_vals[i][0]
      i += 1

   return None

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('file', type=argparse.FileType('rb'), help='Input file')
    parser.add_argument('--flash-base-addr', type=lambda x: int(x, 0), help='Flash Base Address')
    parser.add_argument('--flash-size', type=lambda x: int(x, 0), help='Flash Base Address')

    args = parser.parse_args()

    walker = LoaderInputWalker(args.file)
    vector_table_length = estimate_vector_table_length(walker, args.flash_base_addr, args.flash_base_addr + args.flash_size)
    print('Estimated vector table length: %i \n' % vector_table_length)
    walker.seek(0)
    base_address = estimate_base_offset(walker, vector_table_length)
    print('Estimated base address: 0x%08x \n' % base_address)
