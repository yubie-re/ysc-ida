import os
import struct
import idc
import idaapi
import ida_segment
import ida_bytes
from dataclasses import dataclass
import ctypes
import os

PAGE_SIZE = 0x4000

def accept_file(f, n):
  if 'ysc' in os.path.basename(n):
    return 'YSC Script Loader'
  return 0

@dataclass
class script_header:
    table : int
    opcode_size : int
    arg_struct_size : int
    static_size : int
    global_size : int
    native_size : int
    statics : int
    scr_globals : int
    natives : int
    hash_code : int
    ref_count : int
    script_name : int
    string_heaps: int
    string_heaps_size : int

def load_script_header(f):
    
    f.seek(0)
    f.read(16)
    table = int.from_bytes(f.read(8), "little") & 0xFFFFFF
    print("{:x}".format(table))
    f.read(4)
    opcode_size = int.from_bytes(f.read(4), "little")
    print("{:x}".format(opcode_size))
    arg_struct_size = int.from_bytes(f.read(4), "little")
    static_size = int.from_bytes(f.read(4), "little")
    global_size = int.from_bytes(f.read(4), "little")
    native_size = int.from_bytes(f.read(4), "little")
    statics = int.from_bytes(f.read(8), "little") & 0xFFFFFF
    scr_globals = int.from_bytes(f.read(8), "little") & 0xFFFFFF
    natives = int.from_bytes(f.read(8), "little") & 0xFFFFFF
    print(natives)
    f.read(16)
    hash_code = int.from_bytes(f.read(4), "little")
    ref_count = int.from_bytes(f.read(4), "little")
    script_name = int.from_bytes(f.read(8), "little") & 0xFFFFFF
    string_heaps = int.from_bytes(f.read(8), "little") & 0xFFFFFF
    string_heaps_size = int.from_bytes(f.read(4), "little")
    f.read(12)
    return script_header(table, opcode_size, arg_struct_size, static_size, global_size, native_size, statics, scr_globals, natives, hash_code, ref_count, script_name, string_heaps, string_heaps_size)

def get_page_size(page_index, page_count, total_size):
    max_page = page_count - 1
    if page_index > max_page or page_index < 0:
      return 0
    if page_index == max_page:
      return total_size % PAGE_SIZE
    return PAGE_SIZE

def rotate_left(value, count):
    count &= 63
    return ctypes.c_uint64(value << count).value | ctypes.c_uint64(value >> 64-count).value

def load_file(f, neflags, format):
    '''
    load the given file into the current IDA Pro database.
    Args:
      f (file): the file-like object to load.
      neflags (Any): unused
      format (Any): unused
    Returns:
      int: 1 on success, 0 on failure
    '''
    idaapi.set_processor_type('ysc', 3)
    header = load_script_header(f)
    ida_segment.add_segm(0, 0, header.opcode_size, "CODE", "CODE", 0)
    page_count = int(header.opcode_size / PAGE_SIZE) + 1
    offset = 0
    for i in range(0, page_count):
      f.seek(header.table)
      f.read(i * 8)
      #f.seek(int.from_bytes(f.read(8), 'little') & 0xFFFFFF)
      page_size = get_page_size(i, page_count, header.opcode_size)
      f.file2base(int.from_bytes(f.read(8), 'little') & 0xFFFFFF, offset, offset+page_size, 0)
      offset += page_size

    ida_segment.add_segm(0, header.opcode_size, header.opcode_size + header.native_size * 8, "NATIVES", "DATA", 0)
    f.seek(header.natives)
    for i in range(0, header.native_size):
      native = rotate_left(ctypes.c_uint64(int.from_bytes(f.read(8), 'little')).value, i + header.opcode_size)
      ida_bytes.add_qword(header.opcode_size + i * 8, native)
      ida_bytes.create_qword(header.opcode_size + i * 8, 8)
      idaapi.set_name(header.opcode_size + i * 8, "native_{:X}".format(native), idaapi.SN_FORCE)
    
    ida_segment.add_segm(0, header.opcode_size + header.native_size * 8, header.opcode_size + header.native_size * 8 + header.string_heaps_size, "STRINGS", "DATA", 0)
    page_count = int(header.string_heaps_size / PAGE_SIZE) + 1
    offset = header.opcode_size + header.native_size * 8
    for i in range(0, page_count):
      f.seek(header.string_heaps)
      f.read(i * 8)
      page_size = get_page_size(i, page_count, header.string_heaps_size)
      f.file2base(int.from_bytes(f.read(8), 'little') & 0xFFFFFF, offset, offset+page_size, 0)
      offset += page_size
    idaapi.add_entry(0, 0, "start", 1)
    return 1