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

malloc_state_struct = '''
struct malloc_state
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
malloc_chunk_struct = '''
struct malloc_chunk
{
    size_t prev_size;
    size_t size;
    ptr fd;
    ptr bk;
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
        elif arch == '32':
            self._typ2size = {
                'bool':1,
                'byte':1,
                'char':1,
                'int':4,
                'ptr':4,
                'size_t':4
            }
        else:
            raise NotImplementedError("Not supported arch for C_Struct")
        self._arch = arch
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

        self._addr = 0
        self._mem = None

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

    def _addrof(self, var):
        return self._addr + self._offset(var)

    def _sizeof(self, var):
        var_name, var_index = re.findall('^(\w*)\[?(\d+)?\]?$', var)[0]
        typ = self._dict[var_name]['typ']
        num = self._dict[var_name]['num']

        if var_index == '':  # get total size
            return self._typ2size[typ] * num
        else:
            return self._typ2size[typ] # get one size
    
    def _init(self, memdump, addr = 0):
        #assert len(memdump) >= self.size
        if len(memdump) < self._size:
            memdump.ljust(self._size, '\0')
        for v in self._vars:
            typ, name, num = v
            offset = self._offset(name)
            size = self._sizeof(name)
            self._dict[name]['memdump'] = memdump[offset:offset+size]

        self._mem = memdump
        self._addr = addr

    def _new(self, memdump, addr = 0):
        new_obj = C_Struct(self._code, self._arch, self._endian)
        new_obj._init(memdump, addr)

        return new_obj
    def __getattr__(self, var_name):
        
        if var_name in self._dict:
            typ = self._dict[var_name]['typ']
            num = self._dict[var_name]['num']
            memdump = self._dict[var_name]['memdump']

            a_size = self._typ2size[typ]

            unpack = lambda x:x
            if typ == 'int':
                unpack = lambda x:u32(x)
            elif (typ == 'size_t' or typ == 'ptr') and self._arch == '32':
                unpack = lambda x:u32(x)
            elif (typ == 'size_t' or typ == 'ptr') and self._arch == '64':
                unpack = lambda x:u64(x)
            

            if num > 1:
                result = []
                for i in range(num):
                    mem = memdump[i*a_size:i*a_size+a_size]
                    result.append(unpack(mem))
                return result
            else:
                return unpack(memdump)
        else:
            return None
            

MallocState = C_Struct(malloc_state_struct)
MallocChunk = C_Struct(malloc_chunk_struct)

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
        libc_base = self.proc.bases['libc']
        arena_addr = libc_base + self.libc_info['main_arena_offset']
        return MallocState._new(self.arenamem, arena_addr)

    @property
    def heap_chunks(self):
        heap_mem = self.heapmem
        heap_base = self.proc.bases['heap']
        cur_pos = 0
        result = []
        while cur_pos < len(heap_mem):
            cur_block_size = u64(heap_mem[cur_pos+0x8:cur_pos+0x10]) & ~0b111
            memblock = heap_mem[cur_pos:cur_pos+cur_block_size]
            result.append(MallocChunk._new(memblock, cur_pos + heap_base))
            cur_pos = (cur_pos+cur_block_size) & ~0b1111
            

        return result

    @property
    def fastbins(self):
        result = {}
        for index, fastbin_head in enumerate(self.main_arena.fastbinsY):
            fastbin_ptr = fastbin_head
            lst = []
            while fastbin_ptr:
                
                mem = self.proc.read(fastbin_ptr, 0x20)
                chunk = MallocChunk._new(mem, fastbin_ptr)
                lst.append(chunk)
                fd = chunk.fd
                fastbin_ptr = fd

            result[index*0x10+0x20] = lst

        return result

    @property
    def unsortedbins(self):
        result = []
        unsorted_chunk_addr = self.main_arena._addrof('bins[0]') - 0x10
        

        chunk_ptr = unsorted_chunk_addr
        chunk = MallocChunk._new(self.proc.read(chunk_ptr, 0x20), chunk_ptr)
        while chunk.fd != unsorted_chunk_addr:
            chunk_ptr = chunk.fd
            chunk = MallocChunk._new(self.proc.read(chunk_ptr, 0x20), chunk_ptr)
            result.append(chunk)
        
        return result

def show_chunks(chunks, banner=''):
    if type(chunks) == dict:
        for header in sorted(chunks.iterkeys()):
            if type(header) == int:
                print("========{} {}========".format(banner, hex(header)))
            else:
                print("========{} {}========".format(banner, header))
            for chunk in chunks[header]:
                print("chunk({}): prev_size={} size={} fd={} bk={}".format(hex(chunk._addr), hex(chunk.prev_size), hex(chunk.size), hex(chunk.fd), hex(chunk.bk)))

    elif type(chunks) == list:
        print("========{}========".format(banner))
        for chunk in chunks:
            print("chunk({}): prev_size={} size={} fd={} bk={}".format(hex(chunk._addr), hex(chunk.prev_size), hex(chunk.size), hex(chunk.fd), hex(chunk.bk)))
            


if __name__ == '__main__':
    hi = HeapInspector(8463)
    show_chunks(hi.heap_chunks, 'heapchunks')
    show_chunks(hi.unsortedbins, 'unsortedbins')
    show_chunks(hi.fastbins, 'fastbin')
    
    

