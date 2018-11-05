import struct
import re


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


class C_Struct(object):
    '''This class handles memory dump of c structure.
    Attributes:
        _arch (str): '32' or '64'.
        _vars (list): List of vars.
        _dict (dict): Dict of vars.
        _addr (ind): The start address of the memory dump.
        other (str): Defined by `_code`.
    '''
    def __init__(self, code, arch='64', endian='little'):
        '''__init__ method of C_Struct
        Args:
            code (str): The core of C_Struct, check example.
            arch (:obj:str, optional): The arch of target. '64' by default.
                Also support '32'.
            endian (:obj:`str`, optional): The endian. 'little' by default.
                Not support 'big' yet.
        Raises:
            NotImplementedError: If arch is not '64' or '32'.
        Examples:
            >>> code = 'struct test{int a; char b[10];}'
            >>> test = C_Struct(code)
            >>> print(test._vars)
            [('int', 'a', 1), ('char', 'b', 10)]
            >>> print(test.dict)
            {'a': {'memdump': '', 'num': 1, 'typ': 'int'},
             'b': {'memdump': '', 'num': 10, 'typ': 'char'}}
        '''
        if arch == '64':
            self._typ2size = {
                'bool': 1,
                'byte': 1,
                'char': 1,
                'int': 4,
                'ptr': 8,
                'size_t': 8
            }
        elif arch == '32':
            self._typ2size = {
                'bool': 1,
                'byte': 1,
                'char': 1,
                'int': 4,
                'ptr': 4,
                'size_t': 4
            }
        else:
            raise NotImplementedError("Not supported arch for C_Struct")
        self._arch = arch
        self._endian = endian
        self._code = code
        self._struct_name = \
            re.search('^\s*struct\s+(\w+)\s*{', code).groups()[0]
        self._vars = []
        for v in re.findall('\s*(\w*)\ (\w*)\[?(\d+)?\]?;', code):
            typ, name, num = v
            if num == '':
                num = int(1)
            else:
                num = int(num)
            self._vars.append((typ, name, num))

        self._dict = {}
        for v in self._vars:
            typ, name, num = v
            self._dict[name] = {"typ": typ, "memdump": None, "num": num}
        self._addr = 0
        self._mem = None

    @property
    def _size(self):
        '''int: The size of the structure.
        '''
        size = 0
        for v in self._vars:
            typ, name, num = v
            size += self._typ2size[typ] * num
        return size

    def _offset(self, var):
        '''Get the offset of a var.
        Args:
            var (str): Var name. Also support index like 'list[10]'.
        Return:
            int: The offset of the var.
        '''
        offset = 0
        var_name, var_index = re.findall('^(\w*)\[?(\d+)?\]?$', var)[0]
        if var_index == '':
            var_index = 0
        else:
            var_index = int(var_index)
        for v in self._vars:
            typ, name, num = v
            if name == var_name:
                offset += var_index * self._typ2size[typ]
                break
            offset += self._typ2size[typ] * num
        return offset

    def _addrof(self, var):
        '''Get the address of a var.
        Args:
            var (str): Var name. Also support index like 'list[10]'.
        Return:
            int: The address of the var.
        '''
        return self._addr + self._offset(var)

    def _sizeof(self, var):
        '''Get the size of a var.
        Note:
            If var is a list name without index,
            the entire list size will return.
        Args:
            var (str): Var name. Also support index like 'list[10]'.
        Return:
            int: The size of the var.
        '''
        var_name, var_index = re.findall('^(\w*)\[?(\d+)?\]?$', var)[0]
        typ = self._dict[var_name]['typ']
        num = self._dict[var_name]['num']

        if var_index == '':   # get total size
            return self._typ2size[typ] * num
        else:
            return self._typ2size[typ]  # get one size

    def _init(self, memdump, addr=0):
        '''Method to initialize the structure.
        Args:
            memdump (str): The memory dump of the struture.
            addr (int): The start address of the memory dump.
        '''
        # assert len(memdump) >= self.size
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
        '''Copy method of C_Struture.
        '''
        new_obj = C_Struct(self._code, self._arch, self._endian)
        new_obj._init(self._mem, self._addr)
        return new_obj

    def _new(self, memdump, addr=0):
        '''Generating new instance of the structure.
        Note:
            This is important method of C_Struct. Normally a C_Struct
            is used as generator, and use this method to genrate other
            concret instances with memdump and address.
        Args:
            memdump (str): Memory dump of the structure.
            addr (int): Address of the structure.
        Returns:
            C_Struct: The new instance.
        '''
        new_obj = C_Struct(self._code, self._arch, self._endian)
        new_obj._init(memdump, addr)
        return new_obj

    def __getattr__(self, var_name):
        '''Get the value of a var in the structure.
        Note:
            Default methods and vars of C_Struct start with '_'.
        Args:
            var_name (str): The var name.
        Returns:
            int or str or list: size_t, int and ptr will return a number.
                Others will return its memdump. Array will return a list.
        '''
        if var_name in self._dict:
            typ = self._dict[var_name]['typ']
            num = self._dict[var_name]['num']
            memdump = self._dict[var_name]['memdump']

            a_size = self._typ2size[typ]

            unpack = str
            if typ == 'int':
                unpack = u32
            elif (typ == 'size_t' or typ == 'ptr') and self._arch == '32':
                unpack = u32
            elif (typ == 'size_t' or typ == 'ptr') and self._arch == '64':
                unpack = u64
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
'''str: malloc_state of glibc 2.27+ 64bit
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
'''str: malloc_state of glibc 2.27+ 32bit
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
'''str: malloc_state of glibc 2.19 - 2.26 64bit, 2.19 - 2.25 32bit.
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
'''str: malloc_state of glibc 2.26 32bit.
Note:
    malloc_state.fastbinsY is different from other glibc.
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
'''str: malloc_chunk
'''

tcache_perthread_struct = '''
struct tcache_perthread_struct
{
    char counts[64];
    ptr entries[64];
}
'''
'''str: tcache_perthread
'''


def malloc_state_generator(version='2.27', arch='64'):
    '''Generate C_Struct of malloc_state (arena).
    Args:
        version (str): glibc version,  '2.19' - '2.28'.
        arch (str): '64' or '32'
    Returns:
        C_Struct: The corresponding C_Struct.
    '''
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
    '''Generate C_Struct of malloc_chunk.
    Args:
        version (str): glibc version,  '2.19' - '2.28'.
        arch (str): '64' or '32'
    Returns:
        C_Struct: The corresponding C_Struct.
    '''
    return C_Struct(malloc_chunk_struct, arch)


def tcache_struct_generator(version='2.27', arch='64'):
    '''Generate C_Struct of tcache_perthread (tcache).
    Args:
        version (str): glibc version,  '2.19' - '2.28'.
        arch (str): '64' or '32'
    Returns:
        C_Struct: The corresponding C_Struct.
    '''
    return C_Struct(tcache_perthread_struct, arch)
