import re
import tempfile
import shutil
import subprocess
import json
import os


def build_helper(out_dir, size_t=8):
    '''Use gcc to build libc_info.c

    Note:
        The binary name is 'helper'.
    Args:
        out_dir (str): Path of the output dir.
    Returns:
        str: The Path of the compiled libc_info.c
    '''
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    arch = ''
    if size_t == 4:
        arch = '-m32'
    helper_path = '{}/libs/libc_info.c'.format(cur_dir)
    out_path = '{}/helper'.format(out_dir)
    flags = '-w {arch}'.format(arch=arch)
    command = 'gcc {flags} {path} -o {out}'.format(
        flags=flags, path=helper_path, out=out_path)
    result = subprocess.check_output(command.split())
    return out_path


def get_libc_version(path):
    '''Get the libc version.

    Args:
        path (str): Path to the libc.
    Returns:
        str: Libc version. Like '2.29', '2.26' ...
    '''
    content = open(path).read()
    pattern = "libc[- ]([0-9]+\.[0-9]+)"
    result = re.findall(pattern, content)
    if result:
        return result[0]
    else:
        return ""


def get_arena_info(libc_path, size_t=8):
    '''Get the main arena infomation of the libc.

    Args:
        libc_path (str): Path to the libc.
        size_t (int): 8 for 64 bit version, 4 for 32 bit.
    Returns:
        dict: like {'main_arena_offset':0x1e430, 'tcache_enable':False}
    '''
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    if size_t == 8:
        arch = '64'
    else:
        arch = '32'
    libc_version = get_libc_version(libc_path)
    ld_path = "{dir}/libs/libc-{version}/{arch}bit/ld.so.2".format(
        dir=cur_dir, version=libc_version, arch=arch)

    dir_path = tempfile.mkdtemp()
    # use this to build helper
    # helper_path = build_helper(dir_path, size_t=size_t)
    # # use pre-compiled binary
    helper_path = "{dir}/libs/libc_info{arch}".format(dir=cur_dir, arch=arch)
    # libc name have to be libc.so.6
    shutil.copy(libc_path, os.path.join(dir_path, 'libc.so.6'))
    shutil.copy(ld_path, dir_path)
    os.chmod(ld_path, 0b111000000) #rwx

    command = "{ld} --library-path {dir} {helper}".format(
        ld=ld_path, dir=dir_path, helper=helper_path)

    result = subprocess.check_output(command.split())

    shutil.rmtree(dir_path)
    dc = json.JSONDecoder()
    return dc.decode(result)


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
    with open(path) as f:
        arch_code = ord(f.read(0x13)[-1])
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


def get_libc_info(libc_path):
    '''Get the infomation of the libc.
    
    Args:
        libc_path (str): Path to the libc.
    Returns:
        dict: like {'main_arena_offset':0x1e430, 'tcache_enable':True,
            'version':2.27}
    '''
    arch = get_arch(libc_path)
    if arch == '64':
        size_t = 8
    elif arch == '32':
        size_t = 4
    else:
        raise NotImplementedError
    info = {'version': get_libc_version(libc_path)}
    info.update(get_arena_info(libc_path, size_t))

    # malloc_state adjust
    if info['version'] in ['2.27', '2.28']:
        info['main_arena_offset'] -= size_t

    # 32 bit malloc_state.fastbinsY adjust
    if info['version'] in ['2.26', '2.27', '2.28'] and arch == '32':
        info['main_arena_offset'] -= size_t
    return info


def get_offset(binary, symbol):
    '''Experimental function. Not used for now.

    Args:
        binary (str): Path to the binary.
        symbol (str): Symbol to find.
    Returns:
        int: The offset(virtual) of the symbol.
    '''
    cmdline = 'objdump -j .data -d {}'.format(binary)
    p = subprocess.Popen(
        cmdline.split(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
        )
    out, err = p.communicate()
    if p.returncode:
        raise Exception(err)
    pattern = '(\w+) <{}'.format(symbol)
    result = re.findall(pattern, out)
    if result:
        addr = int(result[0], 16)
        return addr
    else:
        raise Exception('Not found {} in {}'.format(symbol, binary))
