import re
import os
import six
import codecs
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

def get_bases(pid):
    '''
    get program, libc, heap, stack bases
    '''
    exe = os.path.realpath("/proc/{}/exe".format(pid))
    bases = {'mapped':0,
             'libc':0,
             'base':0,
             'heap':0,
             'stack':0,}
    maps = vmmap(pid)
    for m in maps[::-1]:   #search backward to ensure getting the base
        if m.mapname == 'mapped':    
            bases['mapped'] = m.start
        if m.mapname.endswith('.so'):
            bases['libc'] = m.start
        if m.mapname == exe:
            bases['base'] = m.start
        if m.mapname == '[stack]':
            bases['stack'] = m.start
        if m.mapname == '[heap]':
            bases['heap'] = m.start
    return bases

def read_mem(pid, addr, size):
    mem = "/proc/{}/mem".format(pid)
    f = open(mem)
    f.seek(addr)
    result = f.read(size)
    f.close()
    return result

def searchmem_by_mapname(pid, mapname, search):
        result = []
        maps = []
        for m in vmmap(pid):
            if m.mapname== mapname:
                maps.append(m)
        for m in maps:
            if "r" in m.perm:
                result += searchmem(pid, m.start, m.end, search)

        return result
    
def searchmem(pid, start, end, search, mem=None):
    result = []
    if end < start:
        (start, end) = (end, start)
    if mem is None:
        mem = read_mem(pid, start, start-end)
    if not mem:
        return result
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
def get_libc(pid):
    for m in vmmap(pid):
        if m.mapname.endswith('.so'):
            return m.mapname