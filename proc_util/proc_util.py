import re
import os
import six
import codecs

LIBC_REGEX = '^[^\0]*libc(?:-[\d\.]+)?\.so(?:\.6)?$'
class Map(object):
    def __init__(self, start, end, perm, mapname):
        self.start = start
        self.end = end
        self.perm = perm
        self.mapname = mapname
    def __repr__(self):
        return 'Map("{}", {}, {}, "{}")'.format(self.mapname, hex(self.start), hex(self.end), self.perm)

    @property
    def range(self):
        return (self.start, self.end)

    def isin(self, addr):
        return addr >= self.start and addr < self.end
    
def vmmap(pid):
    # this code is converted from vmmap of peda
    maps = [] 
    mpath = "/proc/%s/maps" % pid
    #00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
    pattern = re.compile("([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)")
    out = open(mpath).read()
    matches = pattern.findall(out)
    if matches:
        for (start, end, perm, mapname) in matches:
            start = int("0x%s" % start, 16)
            end = int("0x%s" % end, 16)
            if mapname == "":
                mapname = "mapped"
            maps.append(Map(start, end, perm, mapname)) # this is output format
    return maps
class Proc(object):
    def __init__(self, pid):
        self.pid = pid
        with open(self.path) as f:
            self.arch_code = ord(f.read(0x13)[-1])
        x86_mcode = [3,] #i386 only
        x64_mcode = [62,] #amd64 only
        if self.arch_code in x86_mcode:
            self.arch = '32'
        elif self.arch_code in x64_mcode:
            self.arch = '64'
        else:
            raise NotImplementedError('none supported arch. cod {}'.format(self.arch_code))
    @property
    def path(self):
        return os.path.realpath("/proc/{}/exe".format(self.pid))
    @property
    def vmmap(self):
        return vmmap(self.pid)
    def _range_merge(self, lst, range_vec):
        merged = 0
        for i, r in enumerate(lst):
            start, end = r
            if start == range_vec[1]:
                lst[i][0] = range_vec[0]
                merged = 1
                break
            elif end == range_vec[0]:
                lst[i][1] = range_vec[1]
                merged = 1
                break
        if not merged:
            lst.append(range_vec)

        return lst
    @property
    def ranges(self):
        # TODO: non consistent segment
        ranges = {'mapped':[],
                'libc':[],
                'prog':[],
                'heap':[],
                'stack':[],}
        maps = self.vmmap
        for m in maps:
            if m.mapname == 'mapped':
                name = 'mapped'
                ranges[name] = self._range_merge(ranges[name], [m.start, m.end])
            elif re.match(LIBC_REGEX, m.mapname):
                name = 'libc'
                ranges[name] = self._range_merge(ranges[name], [m.start, m.end])
            elif m.mapname == self.path:
                name = 'prog'
                ranges[name] = self._range_merge(ranges[name], [m.start, m.end])
            elif m.mapname == '[stack]':
                name = 'stack'
                ranges[name] = self._range_merge(ranges[name], [m.start, m.end])
            elif m.mapname == '[heap]':
                name = 'heap'
                ranges[name] = self._range_merge(ranges[name], [m.start, m.end])
            else: #non default ones
                name = os.path.basename(m.mapname)
                if name not in ranges:
                    ranges[name] = [[m.start, m.end],]
                else:
                    ranges[name] = self._range_merge(ranges[name], [m.start, m.end])
        return ranges
    @property
    def bases(self):
        '''
        get program, libc, heap, stack bases
        '''
        bases = {'mapped':0,
                'libc':0,
                'prog':0,
                'heap':0,
                'stack':0,}
        maps = self.vmmap
        for m in maps[::-1]:   #search backward to ensure getting the base
            if m.mapname == 'mapped':    
                bases['mapped'] = m.start
            elif re.match(LIBC_REGEX, m.mapname):
                bases['libc'] = m.start
            elif m.mapname == self.path:
                bases['prog'] = m.start
            elif m.mapname == '[stack]':
                bases['stack'] = m.start
            elif m.mapname == '[heap]':
                bases['heap'] = m.start
            else:
                name = os.path.basename(m.mapname)
                bases[name] = m.start
        return bases

    def whereis(self, addr):
        for m in self.vmmap:
            if m.isin(addr):
                if m.mapname == 'mapped': return 'mapped'
                if re.match(LIBC_REGEX, m.mapname): return 'libc'
                if m.mapname == self.path: return 'prog'
                if m.mapname == '[stack]': return 'stack'
                if m.mapname == '[heap]': return 'heap'
                return os.path.basename(m.mapname)
        return ''
    
    def read(self, addr, size):
        if type(addr) == str:
            if '0x' in addr or '0X' in addr: addr = int(addr, 16)
            else: addr = int(addr)
        
        mem = "/proc/{}/mem".format(self.pid)
        f = open(mem)
        f.seek(addr)
        try:
            result = f.read(size)
        except:
            result = ""
            print("error reading: {}:{}".format(hex(addr), hex(size)))
        f.close()
        return result

    def search_in_prog(self, search):
        return self.searchmem_by_mapname(self.path, search)
    def search_in_libc(self, search):
        return self.searchmem_by_mapname(self.libc, search)
    def search_in_heap(self, search):
        return self.searchmem_by_mapname('[heap]', search)
    def search_in_stack(self, search):
        return self.searchmem_by_mapname('[stack]', search)

    def search_in_all(self, search):
        result = []
        for m in vmmap(self.pid):
            if "r" in m.perm:
                result += self.searchmem(m.start, m.end, search)
        return result

    def searchmem_by_mapname(self, mapname, search):
            result = []
            maps = []
            for m in vmmap(self.pid):
                if m.mapname== mapname:
                    maps.append(m)
            for m in maps:
                if "r" in m.perm:
                    result += self.searchmem(m.start, m.end, search)

            return result
        
    def searchmem(self, start, end, search, mem=None):
        result = []
        if end < start:
            (start, end) = (end, start)
        if mem is None:
            mem = self.read(start, abs(start-end))
        if not mem:
            return result
        if isinstance(search, int):
            search = hex(search)
        if isinstance(search, six.string_types) and search.startswith("0x"):
            # hex number
            search = search[2:]
            if len(search) %2 != 0:
                search = "0" + search
            search = codecs.decode(search, 'hex')[::-1]
            search = re.escape(search)
        # Convert search to bytes if is not already
        if not isinstance(search, bytes):
            search = search.encode('utf-8')
        try:
            p = re.compile(search)
        except:
            search = re.escape(search)
            p = re.compile(search)
        found = list(p.finditer(mem))
        for m in found:
            index = 1
            if m.start() == m.end() and m.lastindex:
                index = m.lastindex+1
            for i in range(0,index):
                if m.start(i) != m.end(i):
                    result += [(start + m.start(i), codecs.encode(mem[m.start(i):m.end(i)], 'hex'))]
        return result
    @property
    def libc(self):
        for m in vmmap(self.pid):
            if re.match(LIBC_REGEX, m.mapname):
                return m.mapname

if __name__ == '__main__':
    import sys
    pid = int(sys.argv[1])
    p = Proc(pid)
    #print(vmmap(p.pid))
    print(p.path)
    print(p.libc)
    for key in p.bases:
        print(key, hex(p.bases[key]))
    for result in p.search_in_stack(0x7fffffffe550):
        print(hex(result[0]), result[1])
