import re
import tempfile
import shutil
import subprocess
import json
import os


def build_helper(out_dir, size_t=8):
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    arch = ''
    if size_t==4:
        arch = '-m32'
    helper_path = '{}/helper/libc_info.c'.format(cur_dir)
    out_path = '{}/helper'.format(out_dir)
    flags = '-w {arch}'.format(arch=arch)
    command = 'gcc {flags} {path} -o {out}'.format(flags=flags, path=helper_path, out=out_path)
    result = subprocess.check_output(command.split())
    return out_path

def get_libc_version(path):
    content = open(path).read()
    pattern = "libc[- ]([0-9]+\.[0-9]+)"
    result = re.findall(pattern, content)
    if result:
        return result[0]
    else:
        return ""

def get_arena_info(libc_path, size_t=8):
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    if size_t==8:
        arch = '64'
    else:
        arch = '32'
    libc_version = get_libc_version(libc_path)
    ld_path = "{dir}/libraries/libc-{version}/{arch}bit/ld.so.2".format(dir=cur_dir, version=libc_version, arch=arch)
    
    dir_path = tempfile.mkdtemp()
    #helper_path = build_helper(dir_path, size_t=size_t)  #use this to build helper
    helper_path = "{dir}/helper/libc_info{arch}".format(dir=cur_dir, arch=arch)  #use pre-compiled binary

    shutil.copy(libc_path, os.path.join(dir_path, 'libc.so.6')) #this is really fuck, have to be libc.so.6
    shutil.copy(ld_path, dir_path)

    command = "{ld} --library-path {dir} {helper}".format(ld=ld_path, dir=dir_path, helper=helper_path)

    result = subprocess.check_output(command.split())

    shutil.rmtree(dir_path)
    dc = json.JSONDecoder()
    return dc.decode(result)

def get_arch(path):
    with open(path) as f:
        arch_code = ord(f.read(0x13)[-1])
    x86_mcode = [3,] #i386 only
    x64_mcode = [62,] #amd64 only
    if arch_code in x86_mcode:
        return '32'
    elif arch_code in x64_mcode:
        return '64'
    else:
        raise NotImplementedError('none supported arch. code {}'.format(arch_code))

def get_libc_info(libc_path):
    arch = get_arch(libc_path)
    if arch == '64':size_t = 8
    elif arch == '32':size_t = 4
    else: raise NotImplementedError

    info = {'version':get_libc_version(libc_path)}
    info.update(get_arena_info(libc_path, size_t))

    # malloc_state adjust
    if info['version'] in ['2.27', '2.28']:
        info['main_arena_offset'] -= size_t

    # 32 bit malloc_state.fastbinsY adjust
    if info['version'] in ['2.26', '2.27', '2.28'] and arch == '32':
        info['main_arena_offset'] -= size_t
    
    return info
    
if __name__ == '__main__':
    #t = get_arena_info('./libc.so.6')
    #print(t)
    pass