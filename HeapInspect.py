#!/usr/bin/python2
from proc_util import *
from libc_util import *
from auxiliary import *
import struct
import re
import sys
import os
import argparse


def u64(data):
    '''Unpack 64bit data with little endian.
    Args:
        data (str): Data to unpack.
    Return:
        int: Unpacked value.
    '''
    return struct.unpack('<Q', data.ljust(8, '\0'))[0]


def u32(data):
    '''Unpack 32bit data with little endian.
    Args:
        data (str): Data to unpack.
    Return:
        int: Unpacked value.
    '''
    return struct.unpack('<I', data.ljust(4, '\0'))[0]


def p64(i):
    '''Unpack 64bit int with little endian to data.
    Args:
        int: Value to pack.
    Return:
        data (str): Packed data.
    '''
    return struct.pack('<Q', i)


def p32(i):
    '''Unpack 32bit int with little endian to data.
    Args:
        int: Value to pack.
    Return:
        data (str): Packed data.
    '''
    return struct.pack('<I', i)


class HeapInspector(object):
    '''Core Class to parse heap and arena.
    Attributes:
        pid (int): pid of the monitored process.
        arch (str): '32' or '64'
        libc_path (str): Path to libc.
        libc_version (str): Libc version like '2.23'.
        libc_base (int): Start address of libc.
        heap_base (int): Start address of heap.
    '''
    def __init__(self, pid):
        '''__init__ method of HeapInspector
        Args:
            pid (int): pid of the target process.
        Raises:
            NotImplementedError: for none supported arch.
        '''
        self.pid = pid
        self.proc = Proc(pid)
        self.arch = self.proc.arch
        self.path = self.proc.path
        self.libc_path = self.proc.libc

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

        libc_info = get_libc_info(self.libc_path)
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
        start, end = self.proc.ranges['heap'][0]
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
        heap_mem = self.heapmem
        cur_pos = 0
        result = []
        while cur_pos < len(heap_mem):
            cur_block_size = self.unpack(
                heap_mem[cur_pos+self.size_t:cur_pos+2*self.size_t]
                ) & ~0b111
            # this happens in some 32 bit libc heap
            if cur_block_size == 0:
                cur_pos += 2*self.size_t
                continue
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
        '''HeapRecorder: A record.
        '''
        return HeapRecorder(self)


class HeapRecorder(object):
    '''This Class is implemented for recoding the state of HeapInspector.
    '''
    def __init__(self, hi):
        '''__init__ method.
        Args:
            hi (HeapInspector): the HeapInspector instance.
        '''
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


class HeapShower(object):
    '''Print heap and arena information in detailed mode.
    '''
    def __init__(self, hi, relative=False, w_limit_size=8):
        '''__init__ method of HeapShower.
        Args:
            hi (HeapInspector or HeapRecord): HeapInspector or HeapRecord.
            relative (bool): Show relative addresses.
            w_limit_size (int): Data size limit.
        '''
        self.hi = hi
        self.record = hi.record
        self.relative = relative
        self.w_limit_size = w_limit_size

    def update(self):
        '''Update the HeapRecord.
        '''
        self.record = self.hi.record

    @property
    def heap_chunks(self):
        '''str: formated heapchunks str.
        '''
        return self.chunks(self.record.heap_chunks, 'heapchunks')

    @property
    def fastbins(self):
        '''str: formated fastbins str.
        '''
        return self.indexed_chunks(self.record.fastbins, 'fastbins')

    @property
    def unsortedbins(self):
        '''str: formated unsortedbins str.
        '''
        return self.chunks(self.record.unsortedbins, 'unsortedbins')

    @property
    def smallbins(self):
        '''str: formated smallbins str.
        '''
        return self.indexed_chunks(self.record.smallbins, 'smallbins', -1)

    @property
    def largebins(self):
        '''str: formated largebins str.
        '''
        return self.indexed_chunks(self.record.largebins, 'largebins', -0x3f)

    @property
    def tcache_chunks(self):
        '''str: formated tcache chunks str.
        '''
        return self.indexed_chunks(self.record.tcache_chunks, 'tcache')

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
                    if typ == 'largebins':
                        lines.append(self.large_chunk(chunk))
                    else:
                        lines.append(self.chunk(chunk))
        else:
            lines.append(self.banner('relative ' + typ))
            for index in sorted(chunk_dict.keys()):
                lines.append(self.banner_index('relative ' + typ, index+align))
                chunks = chunk_dict[index]
                for chunk in chunks:
                    if typ == 'largebins':
                        lines.append(self.rela_large_chunk(chunk))
                    else:
                        lines.append(self.rela_chunk(chunk))
        return '\n'.join(lines)

    def banner(self, banner):
        w, h = terminal_size()
        return '{:=^{width}}'.format('  {}  '.format(banner), width=w)

    def banner_index(self, banner, index):
        return '{:}[{:}]:'.format(banner, index)

    def chunk(self, chunk):
        return "chunk({:#x}): prev_size={:<8} size={:<#8x} fd={:<#15x} bk={:<#15x}".format(
            chunk._addr, self.w_limit(chunk.prev_size), chunk.size, chunk.fd, chunk.bk)

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
        if mapname in self.record.bases:
            return (mapname, addr-self.record.bases[mapname])
        else:
            return ('', addr)

    def rela_str(self, addr):
        result = self.relative_addr(addr)
        if result[0]:
            return result[0]+'+'+hex(result[1])
        else:
            return hex(addr)

    def w_limit(self, addr):
        result = hex(addr)
        if len(result) > self.w_limit_size:
            return result[0:6] + '..'
        return result

    def whereis(self, addr):
        for mapname in self.record.ranges:
            lst = self.record.ranges[mapname]
            for r in lst:
                if r[0] <= addr < r[1]:
                    return mapname
        return ''


class PrettyPrinter(object):
    '''Pretty Printer for HeapInspector.
    Note:
        With the shortage of not able to show enough infomation.
        Use HeapShower for detailed infomation.
    '''
    def __init__(self, hi, relative=False):
        '''__init__ method of PrettyPrinter.
        Args:
            hi (HeapInspector or HeapRecord): HeapInspector or HeapRecord.
            relative (bool): Show relative addresses.
        '''
        self.hi = hi
        self.record = hi.record
        self.relative = relative

    def update(self):
        '''Update the HeapRecord.
        '''
        self.record = self.hi.record

    @property
    def fastbins(self):
        '''str: pretty formated fastbins str.
        '''
        lines = []
        header_fmt = color.green('({size:#x})    fastbins[{index}] ')
        for index in sorted(self.record.fastbins.keys()):
            size = 2*self.record.size_t * (index+2)
            chunks = self.record.fastbins[index]
            tail = ''
            for chunk in chunks:
                tail += "-> " + color.blue("{:#x} ".format(chunk._addr))
            line = header_fmt.format(size=size, index=index) + tail
            if tail != '':
                lines.append(line)
        return '\n'.join(lines)

    @property
    def unsortedbins(self):
        '''str: pretty formated unsortedbins str.
        '''
        head = color.magenta('unsortedbins: ')
        tail = ''
        for chunk in self.record.unsortedbins:
            tail += '<-> ' + color.blue("{:#x} ".format(chunk._addr))
        if tail == '':
            tail = color.blue('None')
        return head+tail

    @property
    def smallbins(self):
        '''str: pretty formated smallbins str.
        '''
        lines = []
        header_fmt = color.green('({size:#x})    smallbins[{index}] ')
        for index in sorted(self.record.smallbins.keys()):
            size = 2*self.record.size_t * (index+1)
            chunks = self.record.smallbins[index]
            tail = ''
            for chunk in chunks:
                tail += "<-> " + color.blue("{:#x} ".format(chunk._addr))
            line = header_fmt.format(size=size, index=index-1) + tail
            if tail != '':
                lines.append(line)
        return '\n'.join(lines)

    @property
    def largebins(self):
        '''str: pretty formated largebins str.
        '''
        lines = []
        header_fmt = color.green('largebins[{index}] ')
        for index in sorted(self.record.largebins.keys()):
            size = 2*self.record.size_t * (index+1)
            chunks = self.record.largebins[index]
            tail = ''
            for chunk in chunks:
                tail += "<-> " + \
                    color.blue(
                        "{:#x}".format(chunk._addr) +
                        color.green("({:#x}) ".format(chunk.size & ~0b111))
                        )
            line = header_fmt.format(size=size, index=index-0x3f) + tail
            if tail != '':
                lines.append(line)
        return '\n'.join(lines)

    @property
    def tcache_chunks(self):
        '''str: pretty formated tcache chunks str.
        '''
        lines = []
        header_fmt = color.yellow('({size:#x})    entries[{index}] ')
        for index in sorted(self.record.tcache_chunks.keys()):
            size = 4*self.record.size_t + index*0x10
            chunks = self.record.tcache_chunks[index]
            tail = ''
            for chunk in chunks:
                tail += "-> " + color.blue("{:#x} ".format(
                    chunk._addr+2*self.record.size_t))
            line = header_fmt.format(size=size, index=index) + tail
            if tail != '':
                lines.append(line)

        return '\n'.join(lines)

    @property
    def all(self):
        '''str: pretty formated all infomation of heap.
        '''
        lines = [self.banner('HeapInspect', 'green')]
        lines.append(self.basic)
        lines.append(self.fastbins)
        lines.append(self.smallbins)
        lines.append(self.largebins)
        lines.append(self.tcache_chunks)
        lines.append(
            color.magenta('top: ') +
            color.blue('{:#x}'.format(self.record.main_arena.top))
            )
        lines.append(
            color.magenta('last_remainder: ') +
            color.blue('{:#x}'.format(self.record.main_arena.last_remainder))
            )
        lines.append(self.unsortedbins)
        return '\n'.join(lines)

    @property
    def basic(self):
        return '''libc_version:{}
arch:{}
tcache_enable:{}
libc_base:{}
heap_base:{}'''.format(
            color.yellow(self.record.libc_version),
            color.yellow(self.record.arch),
            color.yellow(self.record.tcache_enable),
            color.blue(hex(self.record.libc_base)),
            color.blue(hex(self.record.heap_base))
        )

    def banner(self, msg, color1='white'):
        w, h = terminal_size()
        return color.__getattr__(color1)(
            '{:=^{width}}'.format('  {}  '.format(msg), width=w))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='HeapInspect.py',
        description='''Inspect your heap by a given pid.
Author:matrix1001
Github:https://github.com/matrix1001/heapinspect''')
    parser.add_argument(
        '--raw',
        action='store_true',
        help='show more detailed chunk info'
        )
    parser.add_argument(
        '--rela',
        action='store_true',
        help='show relative detailed chunk info'
        )
    parser.add_argument(
        'pid',
        type=int,
        help='pid of the process'
        )
    parser.add_argument(
        '-x',
        action='store_false',
        help='''ignore: heapchunks'''
        )

    args = parser.parse_args()
    pid = args.pid
    hi = HeapInspector(pid)
    if args.rela:
        hs = HeapShower(hi)
        hs.relative = True
        if args.x:
            print(hs.heap_chunks)
        print(hs.fastbins)
        print(hs.unsortedbins)
        print(hs.smallbins)
        print(hs.largebins)
        print(hs.tcache_chunks)
    elif args.raw:
        hs = HeapShower(hi)
        if args.x:
            print(hs.heap_chunks)
        print(hs.fastbins)
        print(hs.unsortedbins)
        print(hs.smallbins)
        print(hs.largebins)
        print(hs.tcache_chunks)
    else:
        pp = PrettyPrinter(hi)
        print(pp.all)
