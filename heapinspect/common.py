import struct

def get_arch(path):
    '''
    Get the arch of the binary.

    Args:
        path (str): The absolute/relative path to the binary.
    Returns:
        str: the arch of the binary, 32 or 64.
    Raises:
        NotImplememtedError: if the arch is not x86 or x64.
    Examples:
        >>> print(get_arch('/bin/sh'))
        64
        >>> print(get_arch('./a_32bit_bin'))
        32
    '''
    with open(path, 'rb') as f:
        arch_code = f.read(0x13)[-1]
        if type(arch_code) == str:
            arch_code = ord(arch_code)
    x86_mcode = [3, ]  # i386 only
    x64_mcode = [62, ]  # amd64 only
    if arch_code in x86_mcode:
        return '32'
    elif arch_code in x64_mcode:
        return '64'
    else:
        raise NotImplementedError(
            'none supported arch. code {}'.format(arch_code)
            )

def u64(data):
    '''Unpack 64bit data with little endian.

    Args:
        data (bytes): Data to unpack.
    Return:
        int: Unpacked value.
    '''
    return struct.unpack('<Q', data.ljust(8, b'\0'))[0]


def u32(data):
    '''Unpack 32bit data with little endian.

    Args:
        data (bytes): Data to unpack.
    Return:
        int: Unpacked value.
    '''
    return struct.unpack('<I', data.ljust(4, b'\0'))[0]


def p64(i):
    '''Unpack 64bit int with little endian to data.

    Args:
        int: Value to pack.
    Return:
        data (bytes): Packed data.
    '''
    return struct.pack('<Q', i)


def p32(i):
    '''Unpack 32bit int with little endian to data.

    Args:
        int: Value to pack.
    Return:
        data (bytes): Packed data.
    '''
    return struct.pack('<I', i)