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



class HeapInspector(object):
    def __init__(self, pid):
        self.pid = pid
        self.proc = Proc(pid)
        self.arch = self.proc.arch
        self.libc_path = self.proc.libc

        if self.arch == '32':
            self.size_t = 4
            self.pack = p32
            self.unpack = u32
        elif self.arch == '64':
            self.size_t = 8
            self.pack = p64
            self.unpack = u64
        else: raise NotImplementedError('invalid arch')

        libc_info = get_libc_info(self.libc_path)
        self.libc_version = libc_info['version']
        self.tcache_enable = libc_info['tcache_enable']
        self.main_arena_offset = libc_info['main_arena_offset']

        self.libc_base = self.proc.bases['libc']
        self.heap_base = self.proc.bases['heap']

        self.MallocState = malloc_state_generator(self.libc_version, self.arch)
        self.MallocChunk = malloc_chunk_generator(self.libc_version, self.arch)
        self.TcacheStruct = tcache_struct_generator(self.libc_version, self.arch)

        


    @property
    def heapmem(self):
        start, end = self.proc.ranges['heap'][0]
        return self.proc.read(start, end-start)

    @property
    def arenamem(self):
        arena_size = self.MallocState._size
        arena_addr = self.libc_base + self.main_arena_offset
        return self.proc.read(arena_addr, arena_size)

    @property
    def main_arena(self):
        if self.heap_base == 0: self.heap_base = self.proc.bases['heap'] #just a refresh in case that heap_base = 0
        arena_addr = self.libc_base + self.main_arena_offset
        return self.MallocState._new(self.arenamem, arena_addr)

    @property
    def tcache(self):
        if self.tcache_enable:
            #fucky align
            testmem = self.proc.read(self.proc.bases['heap']+self.size_t, self.size_t)

            if self.unpack(testmem) == 0:
                base_addr = 4*self.size_t + self.proc.bases['heap']
            else:
                base_addr = 2*self.size_t + self.proc.bases['heap']

            
            
            mem = self.proc.read(base_addr, self.TcacheStruct._size)
            return self.TcacheStruct._new(mem, base_addr)
        else:
            return None

    @property
    def heap_chunks(self):
        heap_mem = self.heapmem
        cur_pos = 0
        result = []
        while cur_pos < len(heap_mem):
            cur_block_size = self.unpack(heap_mem[cur_pos+self.size_t:cur_pos+2*self.size_t]) & ~0b111

            if cur_block_size == 0:  #this could be a little bit fucky when it is 32bit libc-2.27
                cur_pos += 2*self.size_t
                continue
                
            memblock = heap_mem[cur_pos:cur_pos+cur_block_size]
            result.append(self.MallocChunk._new(memblock, cur_pos + self.heap_base))

            if self.arch == '64':
                cur_pos = (cur_pos+cur_block_size) & ~0b1111
            elif self.arch == '32':
                cur_pos = (cur_pos+cur_block_size) & ~0b111
            
            if cur_block_size < 2*self.size_t: break
            

        return result

    @property
    def tcache_chunks(self): #fd search, stack like
        if not self.tcache_enable:
            return {}
        result = {}
        for index, entry_ptr in enumerate(self.tcache.entries):
            lst = []
            tranversed = []
            while entry_ptr:
                
                mem = self.proc.read(entry_ptr-2*self.size_t, 4*self.size_t)
                chunk = self.MallocChunk._new(mem, entry_ptr-2*self.size_t)
                lst.append(chunk)
                entry_ptr = chunk.fd
                if entry_ptr in tranversed: break
                else: tranversed.append(entry_ptr)

            if lst != []:
                result[index] = lst

        return result

    @property
    def fastbins(self): #fd search, stack like
        result = {}
        for index, fastbin_head in enumerate(self.main_arena.fastbinsY):
            fastbin_ptr = fastbin_head
            lst = []
            tranversed = []
            while fastbin_ptr:
                
                mem = self.proc.read(fastbin_ptr, 4*self.size_t)
                chunk = self.MallocChunk._new(mem, fastbin_ptr)
                lst.append(chunk)
                fd = chunk.fd
                fastbin_ptr = fd

                if fastbin_ptr in tranversed: break
                else: tranversed.append(fastbin_ptr)

            if lst != []:
                result[index] = lst

        return result

    @property
    def unsortedbins(self):
        result = self.bins(0, 1)
        if result != {}:
            return result[0]
        else:
            return {}

    def bins(self, start=0, end=127, chunk_size=0x20): #bk search, queue like
        result = {}
        for index in range(start, end): #len(self.main_arena.bins)/2
            
            lst = []
            tranversed = []
            head_chunk_addr = self.main_arena._addrof('bins[{}]'.format(index*2)) - 2*self.size_t
            chunk_ptr = head_chunk_addr
            chunk = self.MallocChunk._new(self.proc.read(chunk_ptr, chunk_size), chunk_ptr)
            while chunk.bk != head_chunk_addr:
                chunk_ptr = chunk.bk
                chunk = self.MallocChunk._new(self.proc.read(chunk_ptr, chunk_size), chunk_ptr)
                lst.append(chunk)
            
                if chunk.bk in tranversed: break
                else: tranversed.append(chunk.bk)
                
            if lst != []:
                result[index] = lst

        return result

    @property
    def smallbins(self):
        return self.bins(1, 63)

    @property
    def largebins(self):
        return self.bins(63, 127, 0x30)


    @property
    def record(self):
        return HeapRecorder(self)

class HeapRecorder(object):
    def __init__(self, hi):
        self.pid = hi.pid
        self.arch = hi.arch
        self.libc_version = hi.libc_version
        self.tcache_enable = hi.tcache_enable
        self.libc_path = hi.libc_path
        self.path = hi.proc.path

        self.size_t = hi.size_t
        self.pack = hi.pack
        self.unpack = hi.unpack

        self.main_arena = hi.main_arena
        self.tcache = hi.tcache

        self.heap_chunks = hi.heap_chunks
        self.fastbins = hi.fastbins
        self.unsortedbins = hi.unsortedbins
        self.smallbins = hi.smallbins
        self.largebins = hi.largebins
        self.tcache_chunks = hi.tcache_chunks

        self.libc_base = hi.libc_base
        self.heap_base = hi.heap_base

        self.bases = hi.proc.bases
        self.ranges = hi.proc.ranges

class HeapShower(object):
    def __init__(self, hi, relative=False, w_limit_size=8):
        self.hi = hi
        self.relative = relative
        self.w_limit_size = w_limit_size

    @property
    def heap_chunks(self):
        return self.chunks(self.hi.heap_chunks, 'heapchunks')
    @property
    def fastbins(self):
        return self.indexed_chunks(self.hi.fastbins, 'fastbins')
    @property
    def unsortedbins(self):
        return self.chunks(self.hi.unsortedbins, 'unsortedbins')
    @property
    def smallbins(self):
        return self.indexed_chunks(self.hi.smallbins, 'smallbins', -1)
    @property
    def largebins(self):
        return self.indexed_chunks(self.hi.largebins, 'largebins', -0x3f)
    @property
    def tcache_chunks(self):
        return self.indexed_chunks(self.hi.tcache_chunks, 'tcache')
    def chunks(self, chunks, typ=''):
        lines = []
        if not self.relative:
            lines.append(self.banner(typ))
            for chunk in chunks:
                lines.append(self.chunk(chunk))
        else:
            lines.append(self.banner('relative ' + typ))
            for chunk in chunks:
                lines.append(self.rela_chunk(chunk))
        return '\n'.join(lines)

    def indexed_chunks(self, chunk_dict, typ='', align=0):
        lines = []
        if not self.relative:
            lines.append(self.banner(typ)) 
            for index in sorted(chunk_dict.keys()):
                chunks = chunk_dict[index]
                lines.append(self.banner_index(typ, index+align))
                for chunk in chunks:
                    lines.append(self.chunk(chunk))
        else:
            lines.append(self.banner('relative ' + typ))
            for index in sorted(chunk_dict.keys()):
                lines.append(self.banner_index('relative ' + typ, index+align))
                chunks = chunk_dict[index]
                for chunk in chunks:
                    lines.append(self.rela_chunk(chunk))
        return '\n'.join(lines)
    
    def banner(self, banner):
        return '='*25 + '{:^30}'.format(banner) + '='*25

    def banner_index(self, banner, index):
        return '{:}[{:}]:'.format(banner, index)

    def chunk(self, chunk):
        return "chunk({:#x}): prev_size={:<8} size={:<#8x} fd={:<#15x} bk={:<#15x}".format(chunk._addr, self.w_limit(chunk.prev_size), chunk.size, chunk.fd, chunk.bk)

    def large_chunk(self, chunk):
        return "chunk({:#x}): prev_size={:<8} size={:<#8x} fd={:<#15x} bk={:<#15x} fd_nextsize={:<#15x} bk_nextsize={:<#15x}".format(
            chunk._addr, 
            self.w_limit(chunk.prev_size), 
            chunk.size, 
            chunk.fd, 
            chunk.bk,
            chunk.fd_nextsize,
            chunk.bk_nextsize)

    def rela_chunk(self, chunk):
        return "chunk({:<13}): prev_size={:<8} size={:<#8x} fd={:<13} bk={:<13}".format(
            self.rela_str(chunk._addr), 
            self.w_limit(chunk.prev_size), 
            chunk.size, 
            self.rela_str(chunk.fd), 
            self.rela_str(chunk.bk))

    def rela_large_chunk(self, chunk):
        return "chunk({:<13}): prev_size={:<8} size={:<#8x} fd={:<13} bk={:<13} fd_nextsize={:<13} bk_nextsize={:<13}".format(
            self.rela_str(chunk._addr), 
            self.w_limit(chunk.prev_size), 
            chunk.size, 
            self.rela_str(chunk.fd), 
            self.rela_str(chunk.bk),
            self.rela_str(chunk.fd_nextsize),
            self.rela_str(chunk.bk_nextsize))

    def relative_addr(self, addr):
        mapname = self.whereis(addr)
        if mapname in self.hi.bases:
            return (mapname, addr-self.hi.bases[mapname])
        else:
            return ('', addr)

    def rela_str(self, addr):
        result = self.relative_addr(addr)
        if result[0]: return result[0]+'+'+hex(result[1])
        else: return hex(addr)
    
    def w_limit(self, addr):
        result = hex(addr)
        if len(result) > self.w_limit_size:
            return result[0:6] + '..'
        return result

    def whereis(self, addr):
        for mapname in self.hi.ranges:
            lst = self.hi.ranges[mapname]
            for r in lst:
                if addr >= r[0] and addr < r[1]:
                    return mapname
        return ''
            


if __name__ == '__main__':
    pid = int(sys.argv[1])
    hi = HeapInspector(pid)
    r = hi.record
    print("libc version:{} arch:{} tcache_enable:{} libc_base:{:#x} heap_base:{:#x}".format(
        r.libc_version,
        r.arch,
        r.tcache_enable,
        r.libc_base,
        r.heap_base))
    
    hs = HeapShower(r)
    print(hs.heap_chunks)
    print(hs.fastbins)
    print(hs.unsortedbins)
    print(hs.smallbins)
    print(hs.largebins)
    print(hs.tcache_chunks)

    print('\nrelative mode\n')
    hs.relative = True
    print(hs.heap_chunks)
    print(hs.fastbins)
    print(hs.unsortedbins)
    print(hs.smallbins)
    print(hs.largebins)
    print(hs.tcache_chunks)
    
    
    

