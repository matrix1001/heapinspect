from proc_util import *
from libc_util import *
import struct

def u64(data):
    return struct.unpack('<Q', data.ljust(8, '\0'))[0]
def u32(data):
    return struct.unpack('<I', data.ljust(4, '\0'))[0]

class malloc_state(object):
    def __init__(self, memdump, arch='64', version='2.27'):
        self.memdump = memdump
        if version == '2.27' and arch == '64':
            assert len(memdump) >= 0x898
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

class malloc_chunk(object):
    def __init__(self, memdump, arch='64'):
        self.memdump = memdump
        if arch == '64':
            assert len(memdump) >= 0x20
            self.prev_size = u64(memdump[0:8])
            self.size = u64(memdump[8:16])
            self.fd = u64(memdump[16:24])
            self.bk = u64(memdump[24:32])
            #self.fd_nextsize = u64(memdump[32:40])
            #self.bk_nextsize = u64(memdump[40:48])

def heap_chunk_looper(heap_mem, arch='64'):
    cur_pos = 0
    while cur_pos < len(heap_mem):
        cur_block_size = u64(heap_mem[cur_pos+0x8:cur_pos+0x10]) & ~0b111
        memblock = heap_mem[cur_pos:cur_pos+cur_block_size]
        cur_pos = (cur_pos+cur_block_size) & ~0b1111
        yield malloc_chunk(memblock)

if __name__ == '__main__':
    p = Proc(21411)
    libc = p.libc
    libc_info = get_libc_info(libc)
    libc_base = p.bases['libc']

    main_arena_mem = p.read(libc_base + libc_info['main_arena_offset'], 0x898)
    main_arena = malloc_state(main_arena_mem)

    heap_base = p.bases['heap']
    heap_mem = p.read(heap_base, main_arena.top-heap_base)
    for chunk in heap_chunk_looper(heap_mem):
        print("chunk: psize={} size={} fd={} bk={}".format(hex(chunk.prev_size), hex(chunk.size), hex(chunk.fd), hex(chunk.bk)))
    

