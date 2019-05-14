from subprocess import Popen, PIPE
import os
from os.path import abspath, basename
from time import sleep

import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir) 

# import from parentdir
from core import *

def create_process(dir_path, file_path):
    ld_path = os.path.join(dir_path, 'ld.so.2')
    command = "{ld} --library-path {dir} {bin}".format(ld=ld_path, dir=dir_path, bin=file_path)
    print("test case {} at {}".format(basename(file_path), dir_path))
    p = Popen(command.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
    print("pid:{}".format(p.pid))
    return p

def show_all(pid):
    hi = HeapInspector(pid)
    hs = HeapShower(hi.record)
    #hs.relative = 1
    #print(hs.heap_chunks)
    print(hs.fastbins)
    print(hs.unsortedbins)
    print(hs.smallbins)
    print(hs.largebins)
    print(hs.tcache_chunks)
    print('')

if __name__ == '__main__':
    testbins = ['./fastbins', './bins', './unsortedbins']
    testcases = [
		'../libs/libc-2.19/',
        '../libs/libc-2.23/',
        '../libs/libc-2.24/',
        '../libs/libc-2.25/', 
        '../libs/libc-2.26/', 
        '../libs/libc-2.27/',
        '../libs/libc-2.28/',
        '../libs/libc-2.29/']

    for binary in testbins:
        binary32 = abspath(binary+'32')
        for case in testcases:
            dirname = os.path.join(abspath(case), '32bit')
            if os.path.exists(dirname):
                p = create_process(dirname, binary32)
                sleep(0.5)
                show_all(p.pid)
                raw_input('press enter')
                p.terminate()


        
        binary64 = abspath(binary+'64')
        for case in testcases:
            dirname = os.path.join(abspath(case), '64bit')
            if os.path.exists(dirname):
                p = create_process(dirname, binary64)
                sleep(0.5)
                show_all(p.pid)
                raw_input('press enter')
                p.terminate()
