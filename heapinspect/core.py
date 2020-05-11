import struct
import re
import sys
import os

from heapinspect.proc import Proc
from heapinspect.libc import get_libc_info 
from heapinspect.c_struct import malloc_state_generator
from heapinspect.c_struct import malloc_chunk_generator
from heapinspect.c_struct import tcache_struct_generator
from heapinspect.layout import HeapShower
from heapinspect.layout import PrettyPrinter
from heapinspect.diff import heapdiff
from heapinspect.common import u64
from heapinspect.common import u32
from heapinspect.common import p64
from heapinspect.common import p32


class HeapInspector(object):
    '''Core Class to parse heap and arena.

    Attributes:
        pid (int): pid of the monitored process.
        arch (str): '32' or '64'.
        libc_path (str): Path to libc.
        libc_version (str): Libc version like '2.23'.
        libc_base (int): Start address of libc.
        heap_base (int): Start address of heap. 
    Args:
        pid (int): pid of the target process.
    Raises:
        NotImplementedError: for none supported arch.
    '''
    def __init__(self, pid):
        self.pid = pid
        self.proc = Proc(pid)
        self.arch = self.proc.arch
        self.path = self.proc.path
        self.libc_path = self.proc.libc
        self.ld_path = self.proc.ld

        if self.arch == '32':
            self.size_t = 4
            self.pack = p32
            self.unpack = u32
        elif self.arch == '64':
            self.size_t = 8
            self.pack = p64
            self.unpack = u64
        else:
            raise NotImplementedError('invalid arch')

        libc_info = get_libc_info(self.libc_path, self.proc.ld)
        self.libc_version = libc_info['version']
        self.tcache_enable = libc_info['tcache_enable']
        self.main_arena_offset = libc_info['main_arena_offset']

        self.libc_base = self.proc.bases['libc']
        self.heap_base = self.proc.bases['heap']

        self.MallocState = malloc_state_generator(
            self.libc_version,
            self.arch
            )
        self.MallocChunk = malloc_chunk_generator(
            self.libc_version,
            self.arch
            )
        self.TcacheStruct = tcache_struct_generator(
            self.libc_version,
            self.arch
            )

    @property
    def ranges(self):
        '''dict: vmmap ranges.
        '''
        return self.proc.ranges

    @property
    def bases(self):
        '''dict: vmmap start addresses.
        '''
        return self.proc.bases

    @property
    def heapmem(self):
        '''str: heap memory dump.
        '''
        try:
            start, end = self.proc.ranges['heap'][0]
        except IndexError:
            raise Exception("Heap not initialized")
        return self.proc.read(start, end-start)

    @property
    def arenamem(self):
        '''str: main_arena memory dump.
        '''
        arena_size = self.MallocState._size
        arena_addr = self.libc_base + self.main_arena_offset
        return self.proc.read(arena_addr, arena_size)

    @property
    def main_arena(self):
        '''C_Struct: main_arena
        '''
        if self.heap_base == 0:
            # just a refresh in case that heap_base = 0
            self.heap_base = self.proc.bases['heap']
        arena_addr = self.libc_base + self.main_arena_offset
        return self.MallocState._new(self.arenamem, arena_addr)

    @property
    def tcache(self):
        '''C_Struct: tcache perthread
        '''
        if self.tcache_enable:
            testmem = self.proc.read(
                self.proc.bases['heap']+self.size_t, self.size_t)
            # this happens in some 32 bit libc heap
            if self.unpack(testmem) == 0:
                base_addr = 4 * self.size_t + self.proc.bases['heap']
            else:
                base_addr = 2 * self.size_t + self.proc.bases['heap']

            mem = self.proc.read(base_addr, self.TcacheStruct._size)
            return self.TcacheStruct._new(mem, base_addr)
        else:
            return None

    @property
    def heap_chunks(self):
        '''list(C_Struct): list of heap chunks.
        '''
        if self.heap_base == 0:
            # just a refresh in case that heap_base = 0
            self.heap_base = self.proc.bases['heap']
        heap_mem = self.heapmem
        cur_pos = 0
        # check if there is an alignment at the start of the heap.
        first_chunk_size = self.unpack(self.heapmem[self.size_t: self.size_t * 2])
        if first_chunk_size == 0:
            cur_pos += 2*self.size_t
        result = []
        while cur_pos < len(heap_mem):
            cur_block_size = self.unpack(
                heap_mem[cur_pos+self.size_t:cur_pos+2*self.size_t]
                ) & ~0b111
            memblock = heap_mem[cur_pos:cur_pos+cur_block_size]
            result.append(self.MallocChunk._new(
                    memblock,
                    cur_pos + self.heap_base))
            if self.arch == '64':
                cur_pos = (cur_pos+cur_block_size) & ~0b1111
            elif self.arch == '32':
                cur_pos = (cur_pos+cur_block_size) & ~0b111
            if cur_block_size < 2*self.size_t:
                break
        return result

    @property
    def tcache_chunks(self):
        '''dict: dict of tcache_chunks.
        '''
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
                if entry_ptr in tranversed:
                    break
                else:
                    tranversed.append(entry_ptr)
            if lst != []:
                result[index] = lst
        return result

    @property
    def fastbins(self):
        '''dict: dict of fastbins.
        '''
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
                if fastbin_ptr in tranversed:
                    break
                else:
                    tranversed.append(fastbin_ptr)
            if lst != []:
                result[index] = lst
        return result

    @property
    def unsortedbins(self):
        '''list: list of unsortedbins.
        '''
        result = self.bins(0, 1)
        if result != {}:
            return result[0]
        else:
            return {}

    def bins(self, start=0, end=127, chunk_size=0x20):
        '''Generate bins of the arena.

        Note:
            malloc_state has 127 bins. bins[0] is unsortedbins,
            bins[1] - bins[62] are smallbins,
            bins[63] - bins[126] are largebins.
        Args:
            strat (:obj:`int`, optional): Start positions.
        '''
        result = {}
        for index in range(start, end):
            lst = []
            tranversed = []
            head_chunk_addr = self.main_arena._addrof(
                'bins[{}]'.format(index * 2)
                ) - 2 * self.size_t

            chunk_ptr = head_chunk_addr
            chunk = self.MallocChunk._new(
                self.proc.read(chunk_ptr, chunk_size), chunk_ptr)
            while chunk.bk != head_chunk_addr:
                chunk_ptr = chunk.bk
                chunk = self.MallocChunk._new(
                    self.proc.read(chunk_ptr, chunk_size),
                    chunk_ptr)
                lst.append(chunk)
                if chunk.bk in tranversed:
                    break
                else:
                    tranversed.append(chunk.bk)
            if lst != []:
                result[index] = lst
        return result

    @property
    def smallbins(self):
        '''dict: dict of smallbins.
        '''
        return self.bins(1, 63)

    @property
    def largebins(self):
        '''dict: dict of largebins.
        '''
        return self.bins(63, 127, 0x30)

    @property
    def record(self):
        '''HeapRecord: A record.
        '''
        return HeapRecord(self)


class HeapRecord(object):
    '''This Class is implemented for recording the state of HeapInspector.

    Args:
        hi (HeapInspector): the HeapInspector instance.
    '''
    def __init__(self, hi):
        self.pid = hi.pid
        self.arch = hi.arch
        self.libc_version = hi.libc_version
        self.tcache_enable = hi.tcache_enable
        self.libc_path = hi.libc_path
        self.path = hi.path

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

        self.bases = hi.bases
        self.ranges = hi.ranges

    @property
    def record(self):
        return self
