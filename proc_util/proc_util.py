import re
import os
import six
import codecs

LIBC_REGEX = '^[/\w-]*libc(?:-[\d\.]+)?\.so(?:\.6)?$'
class Map(object):
    def __init__(self, start, end, perm, mapname):
        self.start = start
        self.end = end
        self.perm = perm
        self.mapname = mapname
    def __repr__(self):
        return 'Map("{}", {}, {}, "{}")'.format(self.mapname, hex(self.start), hex(self.end), self.perm)
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
    @property
    def path(self):
        return os.path.realpath("/proc/{}/exe".format(self.pid))
    @property
    def vmmap(self):
        return vmmap(self.pid)
    @property
    def bases(self):
        '''
        get program, libc, heap, stack bases
        '''
        exe = self.path
        bases = {'mapped':0,
                'libc':0,
                'base':0,
                'heap':0,
                'stack':0,}
        maps = vmmap(self.pid)
        for m in maps[::-1]:   #search backward to ensure getting the base
            if m.mapname == 'mapped':    
                bases['mapped'] = m.start
            if re.match(LIBC_REGEX, m.mapname):
                bases['libc'] = m.start
            if m.mapname == exe:
                bases['base'] = m.start
            if m.mapname == '[stack]':
                bases['stack'] = m.start
            if m.mapname == '[heap]':
                bases['heap'] = m.start
        return bases

    def read(self, addr, size):
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
