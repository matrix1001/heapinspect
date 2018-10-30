import struct
import re
def u64(data):
    return struct.unpack('<Q', data.ljust(8, '\0'))[0]
def u32(data):
    return struct.unpack('<I', data.ljust(4, '\0'))[0]
def p64(i):
    return struct.pack('<Q', i)
def p32(i):
    return struct.pack('<I', i)


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


malloc_state_struct_new_64 = '''
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
malloc_state_struct_new_32 = '''
struct malloc_state
{
    int mutex;
    int flags;
    int have_fastchunks;
    ptr fastbinsY[11];
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
malloc_state_struct_old = '''
struct malloc_state
{
    int mutex;
    int flags;
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
malloc_state_struct_26_32 = '''
struct malloc_state
{
    int mutex;
    int flags;
    ptr fastbinsY[11];
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

def malloc_state_generator(version='2.27', arch='64'):
    if arch == '32' and version == '2.26':
        return C_Struct(malloc_state_struct_26_32, arch)
    elif version in ['2.27', '2.28']:
        if arch == '64':
            return C_Struct(malloc_state_struct_new_64, arch)
        elif arch == '32':
            return C_Struct(malloc_state_struct_new_32, arch)
    else:
        return C_Struct(malloc_state_struct_old, arch)

def malloc_chunk_generator(version='2.27', arch='64'):
    return C_Struct(malloc_chunk_struct, arch)

def tcache_struct_generator(version='2.27', arch='64'):
    return C_Struct(tcache_perthread_struct, arch)
