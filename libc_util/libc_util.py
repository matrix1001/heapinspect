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
        arch = '64bit'
    else:
        arch = '32bit'
    libc_version = get_libc_version(libc_path)
    ld_path = "{dir}/libraries/libc-{version}/{arch}/ld.so.2".format(dir=cur_dir, version=libc_version, arch=arch)
    
    dir_path = tempfile.mkdtemp()
    helper_path = build_helper(dir_path, size_t=size_t)

    shutil.copy(libc_path, os.path.join(dir_path, 'libc.so.6')) #this is really fuck, have to be libc.so.6
    shutil.copy(ld_path, dir_path)

    command = "{ld} --library-path {dir} {helper}".format(ld=ld_path, dir=dir_path, helper=helper_path)

    result = subprocess.check_output(command.split())

    shutil.rmtree(dir_path)
    dc = json.JSONDecoder()
    return dc.decode(result)

def get_libc_info(libc_path, arch='64'):
    new_versions = ['2.27', '2.28']
    info = {'version':get_libc_version(libc_path)}
    if arch == '64':
        info.update(get_arena_info(libc_path, 8))
    elif arch == '32':
        info.update(get_arena_info(libc_path, 4))
    if info['version'] in new_versions:
        
        info['main_arena_offset'] = info['main_arena_offset']-8
    return info
    
if __name__ == '__main__':
    #t = get_arena_info('./libc.so.6')
    #print(t)
    pass