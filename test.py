from proc_util import *
from libc_util import *
import struct

def u64(data):
    return struct.unpack('<Q', data.ljust(8, '\0'))[0]
def u32(data):
    return struct.unpack('<I', data.ljust(4, '\0'))[0]
    
class Arena(object):
    def __init__(self, memdump):
        self.mutex = u32(memdump[0:4])
        self.flags = u32(memdump[4:8])
        self.have_fastchunks = u32(memdump[8:12])
        self.fastbinsY = []
        for i in range(10):
            self.fastbinsY.append(u64(memdump[16+8*i:24+8*i]))
        self.top = u64(memdump[0x60:0x68])
        self.last_remainder = u64(memdump[0x68:0x70])
        self.bins = []
        for i in range(254):
            self.bins.append(u64(memdump[0x70+i*8:0x78+i*8]))
        self.binmap = []
        for i in range(4):
            self.binmap.append(u64(memdump[0x860+i*4:0x864+i*4]))
        self.next = u64(memdump[0x870:0x878])
        self.next_free = u64(memdump[0x878:0x880])
        self.attached_threads = u64(memdump[0x880:0x888])
        self.system_mem = u64(memdump[0x888:0x890])
        self.max_system_mem = u64(memdump[0x890:0x898])
pid = 21411
libc_path = get_libc(pid)

libc_info = get_libc_info(libc_path)

bases = get_bases(pid)
libc_base = bases['libc']
arena_addr = libc_info['main_arena_offset'] + libc_base

arena_dump = read_mem(pid, arena_addr, 0x898)
arena_obj = Arena(arena_dump)