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

class HeapInspector(object):
    def __init__(self, pid):
        self.pid = pid
        self.proc = Proc(pid)
        self.libc_path = self.proc.libc
        self.libc_info = get_libc_info(self.libc_path)

    @property
    def heapmem(self):
        start, end = 0xffffffffffffffffff, 0
        for m in self.proc.vmmap:
            if m.mapname == '[heap]':
                if m.start < start:
                    start = m.start
                if m.end > end:
                    end = m.end
        return self.proc.read(start, end-start)

    @property
    def arenamem(self):
        libc_base = self.proc.bases['libc']
        arena_size = 0x898
        arena_addr = libc_base + self.libc_info['main_arena_offset']
        return self.proc.read(arena_addr, arena_size)

    @property
    def main_arena(self):
        return malloc_state(self.arenamem)

    @property
    def heap_chunks(self):
        heap_mem = self.heapmem
        cur_pos = 0
        result = []
        while cur_pos < len(heap_mem):
            cur_block_size = u64(heap_mem[cur_pos+0x8:cur_pos+0x10]) & ~0b111
            memblock = heap_mem[cur_pos:cur_pos+cur_block_size]
            cur_pos = (cur_pos+cur_block_size) & ~0b1111
            result.append(malloc_chunk(memblock))

        return result

    @property
    def fastbins(self):
        result = {}
        for index, fastbin_head in enumerate(self.main_arena.fastbinsY):
            fastbin_ptr = fastbin_head
            lst = []
            while fastbin_ptr:
                
                mem = self.proc.read(fastbin_ptr, 0x20)
                chunk = malloc_chunk(mem)
                lst.append(chunk)
                fd = chunk.fd
                fastbin_ptr = fd

            result[index*0x10+0x20] = lst

        return result

    @property
    def unsortedbins(self):
        result = []
        unsorted_ptr = self.main_arena.last_remainder
        while unsorted_ptr:
            mem = self.proc.read(unsorted_ptr, 0x20)
            chunk = malloc_chunk(mem)
            lst.append(chunk)
            fd = chunk.fd
            bk = chunk.bk
            unsorted_ptr = fd
            

if __name__ == '__main__':
    hi = HeapInspector(21411)
    for chunk in hi.heap_chunks:
        print("chunk: psize={} size={} fd={} bk={}".format(hex(chunk.prev_size), hex(chunk.size), hex(chunk.fd), hex(chunk.bk)))
    
    

