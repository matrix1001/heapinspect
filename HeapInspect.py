from proc_util import *
from libc_util import *
from c_struct import malloc_state_generator, malloc_chunk_generator, tcache_struct_generator
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

        libc_info = get_libc_info(self.libc_path, self.arch)
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
            base_addr = self.proc.bases['heap'] + 2*self.size_t
            
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
        self.main_arena = hi.main_arena
        self.tcache = hi.tcache

        self.heap_chunks = hi.heap_chunks
        self.fastbins = hi.fastbins
        self.unsortedbins = hi.unsortedbins
        self.smallbins = hi.smallbins
        self.largebins = hi.largebins
        self.tcache_chunks = hi.tcache_chunks

        self.bases = hi.proc.bases
        self.ranges = hi.proc.ranges

class HeapShower(object):
    def __init__(self, hi, relative=False, w_limit_size=8):
        self.hi = hi
        self.relative = relative
        self.w_limit_size = w_limit_size

    def heap_chunks(self):
        chunks = hi.heap_chunks
        if not self.relative:
            print('='*30 + '{:^20}'.format('heapchunks') + '='*30)
            for chunk in chunks:
                self.show_chunk(chunk)
        else:
            print('='*25 + '{:^30}'.format('relative heapchunks') + '='*25)
            for chunk in chunks:
                self.show_rela_chunk(chunk)

    def fastbins(self):
        if not self.relative:
            print('='*30 + '{:^20}'.format('fastbins') + '='*30)
            for index in self.hi.fastbins:
                chunks = self.hi.fastbins[index]
                print('='*30 + '{:^13} {:<#6x}'.format('fastbins', index*0x10+0x10) + '='*30)
                for chunk in chunks:
                    self.show_chunk(chunk)
        else:
            print('='*25 + '{:^30}'.format('relative fastbins') + '='*25)
            for index in self.hi.fastbins:
                print('='*25 + '{:^23} {:<#6x}'.format('relative fastbins', index*0x10+0x10) + '='*25)
                chunks = hi.fastbins[index]
                for chunk in chunks:
                    self.show_rela_chunk(chunk)

    def unsortedbins(self):
        chunks = hi.unsortedbins
        if not self.relative:
            print('='*30 + '{:^20}'.format('unsortedbins') + '='*30)
            for chunk in chunks:
                self.show_chunk(chunk)
        else:
            print('='*25 + '{:^30}'.format('relative unsortedbins') + '='*25)
            for chunk in chunks:
                self.show_rela_chunk(chunk)

    def smallbins(self):
        if not self.relative:
            print('='*30 + '{:^20}'.format('smallbins') + '='*30)
            for index in self.hi.smallbins:
                chunks = self.hi.smallbins[index]
                print('='*30 + '{:^13} {:<#6x}'.format('smallbins', index*0x10+0x10) + '='*30)
                for chunk in chunks:
                    self.show_chunk(chunk)
        else:
            print('='*25 + '{:^30}'.format('relative smallbins') + '='*25)
            for index in self.hi.smallbins:
                print('='*25 + '{:^23} {:<#6x}'.format('relative smallbins', index*0x10+0x10) + '='*25)
                chunks = hi.smallbins[index]
                for chunk in chunks:
                    self.show_rela_chunk(chunk)
    def largebins(self):
        if not self.relative:
            print('='*30 + '{:^20}'.format('largebins') + '='*30)
            for index in self.hi.largebins:
                chunks = self.hi.largebins[index]
                print('='*30 + '{:^13} {:<#6x}'.format('largebins', index) + '='*30)
                for chunk in chunks:
                    self.show_chunk(chunk)
        else:
            print('='*25 + '{:^30}'.format('relative largebins') + '='*25)
            for index in self.hi.largebins:
                print('='*25 + '{:^23} {:<#6x}'.format('relative largebins', index) + '='*25)
                chunks = hi.largebins[index]
                for chunk in chunks:
                    self.show_rela_chunk(chunk)


    def tcache_chunks(self):
        if not self.relative:
            print('='*30 + '{:^20}'.format('tcache') + '='*30)
            for index in self.hi.tcache_chunks:
                chunks = self.hi.tcache_chunks[index]
                print('='*30 + '{:^13} {:<#6x}'.format('tcache', index*0x10+0x10) + '='*30)
                for chunk in chunks:
                    self.show_chunk(chunk)
        else:
            print('='*25 + '{:^30}'.format('relative tcache') + '='*25)
            for index in self.hi.tcache_chunks:
                print('='*25 + '{:^23} {:<#6x}'.format('relative tcache', index*0x10+0x10) + '='*25)
                chunks = hi.tcache_chunks[index]
                for chunk in chunks:
                    self.show_rela_chunk(chunk)


    def show_chunk(self, chunk):
        print("chunk({:#x}): prev_size={:<8} size={:<#8x} fd={:<#15x} bk={:<#15x}".format(chunk._addr, self.w_limit(chunk.prev_size), chunk.size, chunk.fd, chunk.bk))

    def show_rela_chunk(self, chunk):
        print("chunk({:<13}): prev_size={:<8} size={:<#8x} fd={:<13} bk={:<13}".format(
            self.rela_str(chunk._addr), 
            self.w_limit(chunk.prev_size), 
            chunk.size, 
            self.rela_str(chunk.fd), 
            self.rela_str(chunk.bk)))

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
    print("libc version:{} arch:{} tcache_enable:{} libc_base:{:#x} heap_base:{:#x}".format(
        hi.libc_version,
        hi.arch,
        hi.tcache_enable,
        hi.libc_base,
        hi.heap_base))
    r = hi.record
    hs = HeapShower(r)
    hs.heap_chunks()
    hs.fastbins()
    hs.unsortedbins()
    hs.smallbins()
    hs.largebins()
    hs.tcache_chunks()

    print('\nrelative mode\n')
    hs.relative = True
    hs.heap_chunks()
    hs.fastbins()
    hs.unsortedbins()
    hs.smallbins()
    hs.largebins()
    hs.tcache_chunks()
    
    
    

