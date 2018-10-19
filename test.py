from proc_util import *
from libc_util import *
import struct
import ctypes
import re
import copy

def u64(data):
    return struct.unpack('<Q', data.ljust(8, '\0'))[0]
def u32(data):
    return struct.unpack('<I', data.ljust(4, '\0'))[0]
def p64(i):
    return struct.pack('<Q', i)
def p32(i):
    return struct.pack('<I', i)

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

class tcache_perthread_struct(object):
    def __init__(self, memdump, arch='64'):
        self.memdump = memdump
        self.counts = []
        self.entries = []
        if arch == '64':
            assert len(memdump) >= 0x240
            for i in range(64):
                self.counts.append(ord(memdump[i]))
                self.entries.append(ord(memdump[i*8+64]))

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
            
sample = '''
struct test
{
    int mutex;
    int flags;
    int have_fastchunks;
    int align;
    ptr fastbinsY[10];
    ptr top;
    ptr last_remainder;
    ptr bins[254];
    int binmap[4];
    ptr next;
    ptr next_free;
    size_t attached_threads;
    size_t system_mem;
    size_t max_system_mem;
}
'''
sample = '''
struct malloc_chunk
{
    size_t prev_size;
    size_t size;
    ptr p[2];
}
'''
class C_Struct(object):
    def __init__(self, code, arch='64', endian='little'):
        if arch == '64':
            self._typ2size = {
                'bool':1,
                'byte':1,
                'char':1,
                'int':4,
                'ptr':8,
                'size_t':8
            }
        self._endian = endian
        self._code = code
        self._struct_name = re.search('^\s*struct\s+(\w+)\s*{', code).groups()[0]
        self._vars = []
        for v in re.findall('\s*(\w*)\ (\w*)\[?(\d+)?\]?;', code):
            typ, name, num = v
            if num == '': num = int(1)
            else: num = int(num)
            self._vars.append((typ, name, num))
    
        self._dict = {}
        for v in self._vars:
            typ, name, num = v
            self._dict[name] = {"typ":typ, "memdump":None, "num":num}

    @property
    def _size(self):
        size = 0
        for v in self._vars:
            typ, name, num = v
            
            size += self._typ2size[typ] * num
        return size

    def _offset(self, var):
        offset = 0
        var_name, var_index = re.findall('^(\w*)\[?(\d+)?\]?$', var)[0]
        if var_index == '': var_index = 0
        else: var_index = int(var_index)
        for v in self._vars:
            typ, name, num = v
            if name == var_name:
                offset += var_index * self._typ2size[typ]
                break
            
            offset += self._typ2size[typ] * num
        return offset

    def _sizeof(self, var):
        var_name, var_index = re.findall('^(\w*)\[?(\d+)?\]?$', var)[0]
        typ = self._dict[var_name]['typ']
        num = self._dict[var_name]['num']

        if var_index == '':  # get total size
            return self._typ2size[typ] * num
        else:
            return self._typ2size[typ] # get one size
    
    def _new(self, memdump):
        #assert len(memdump) >= self.size
        if len(memdump) < self._size:
            memdump.ljust(self._size, '\0')
        for v in self._vars:
            typ, name, num = v
            offset = self._offset(name)
            size = self._sizeof(name)
            self._dict[name]['memdump'] = memdump[offset:offset+size]

        return copy.copy(self)
    def __getattr__(self, var_name):
        
        typ = self._dict[var_name]['typ']
        num = self._dict[var_name]['num']
        memdump = self._dict[var_name]['memdump']

        a_size = self._typ2size[typ]

        if num > 1:
            result = []
            for i in range(num):
                mem = memdump[i*a_size:i*a_size+a_size]
                result.append(mem)
            return result
        else:
            return memdump
            

a = C_Struct(sample)
mem = p64(0x60) + p64(0x20) + p64(0xdeadbeef) + p64(0)
b = a._new(mem)

    #def __getattr__(self, attr):






if __name__ == '__main__':
    hi = HeapInspector(21411)
    for chunk in hi.heap_chunks:
        print("chunk: psize={} size={} fd={} bk={}".format(hex(chunk.prev_size), hex(chunk.size), hex(chunk.fd), hex(chunk.bk)))
    
    

