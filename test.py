from proc_util import *
from libc_util import *
import struct
import re
import sys

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
    ptr fd_nextsize;
    ptr bk_nextsize;
}
'''

tcache_perthread_struct = '''
struct tcache_perthread_struct
{
    char counts[64];
    ptr entries[64];
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


    def _copy(self):
        new_obj = C_Struct(self._code, self._arch, self._endian)
        new_obj._init(self._mem, self._addr)
        return new_obj

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
TcacheStruct = C_Struct(tcache_perthread_struct)

class HeapInspector(object):
    def __init__(self, pid):
        self.pid = pid
        self.proc = Proc(pid)
        self.libc_path = self.proc.libc
        self.libc_info = get_libc_info(self.libc_path)

    @property
    def heapmem(self):
        start, end = self.proc.ranges['heap'][0]
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
    def tcache(self):
        if self.libc_info['tcache_enable']:
            base_addr = self.proc.bases['heap'] + 0x10
            
            mem = self.proc.read(base_addr, TcacheStruct._size)
            return TcacheStruct._new(mem, base_addr)
        else:
            return None

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
    def tcache_chunks(self):
        result = {}
        for index, entry_ptr in enumerate(self.tcache.entries):
            lst = []
            while entry_ptr:
                
                mem = self.proc.read(entry_ptr-0x10, 0x20)
                chunk = MallocChunk._new(mem, entry_ptr-0x10)
                lst.append(chunk)
                entry_ptr = chunk.fd

            if lst != []:
                result[index*0x10+0x20] = lst

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

            if lst != []:
                result[index*0x10+0x20] = lst

        return result

    @property
    def unsortedbins(self):
        result = self.bins(0, 1)
        if result != {}:
            return result[0]
        else:
            return {}

    def bins(self, start=0, end=127):
        result = {}
        for index in range(start, end): #len(self.main_arena.bins)/2
            
            lst = []
            head_chunk_addr = self.main_arena._addrof('bins[{}]'.format(index*2)) - 0x10
            chunk_ptr = head_chunk_addr
            chunk = MallocChunk._new(self.proc.read(chunk_ptr, 0x20), chunk_ptr)
            while chunk.fd != head_chunk_addr:
                chunk_ptr = chunk.fd
                chunk = MallocChunk._new(self.proc.read(chunk_ptr, 0x20), chunk_ptr)
                lst.append(chunk)
            
            if lst != []:
                result[index] = lst

        return result

    @property
    def smallbins(self):
        return self.bins(1, 63)

    @property
    def largebins(self):
        return self.bins(63, 127)


    @property
    def record(self):
        return HeapRecorder(self)

class HeapRecorder(object):
    def __init__(self, hi, heap_base=0, libc_base=0):
        self._main_arena = hi.main_arena
        self._heap_chunks = hi.heap_chunks
        self._fastbins = hi.fastbins
        self._unsortedbins = hi.unsortedbins
        self._smallbins = hi.smallbins
        self._largebins = hi.largebins
        self._tcache = hi.tcache_chunks

        self._heap_base = heap_base
        self._libc_base = libc_base


    


def show_chunks(chunks, banner=''):
    if type(chunks) == dict:
        for header in sorted(chunks.iterkeys()):
            if type(header) == int:
                print('='*30 + '{:^20}'.format(banner+' '+hex(header)) + '='*30)
            else:
                print('='*30 + '{:^20}'.format(banner+' '+header) + '='*30)
            for chunk in chunks[header]:
                print("chunk({:<15}): prev_size={:<8} size={:<8} fd={:<15} bk={:<15}".format(hex(chunk._addr), hex(chunk.prev_size), hex(chunk.size), hex(chunk.fd), hex(chunk.bk)))

    elif type(chunks) == list:
        print('='*30 + '{:^20}'.format(banner) + '='*30)
        for chunk in chunks:
            print("chunk({:<15}): prev_size={:<8} size={:<8} fd={:<15} bk={:<15}".format(hex(chunk._addr), hex(chunk.prev_size), hex(chunk.size), hex(chunk.fd), hex(chunk.bk)))
            


if __name__ == '__main__':
    pid = int(sys.argv[1])
    hi = HeapInspector(pid)
    r = hi.record
    show_chunks(r._heap_chunks, 'heapchunks')
    show_chunks(r._fastbins, 'fastbin')
    show_chunks(r._unsortedbins, 'unsortedbins')
    show_chunks(r._smallbins, 'smallbins')
    show_chunks(r._largebins, 'largebins')
    show_chunks(r._tcache, 'tcache')
    
    

