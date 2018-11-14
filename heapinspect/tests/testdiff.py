from pwn import *
from os.path import abspath, basename

import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)

from core import *

def create_process(dir_path, file_path):
    ld_path = os.path.join(dir_path, 'ld.so.2')
    command = "{ld} --library-path {dir} {bin}".format(ld=ld_path, dir=dir_path, bin=file_path)
    print("test case {} at {}".format(basename(file_path), dir_path))
    p = process(command.split())
    print("pid:{}".format(p.pid))
    sleep(0.3)
    return p


def test(p):
    hi = HeapInspector(p.pid)
    # start
    p.send('\n')
    sleep(0.3)
    # stage 1
    record1 = hi.record
    p.send('\n')
    sleep(0.3)
    # stage 2
    record2 = hi.record
    p.send('\n')
    sleep(0.3)
    # stage 3
    record3 = hi.record
    #raw_input()
    # exit
    p.send('\n')
    # now do diff and show
    hs = HeapShower(record1)
    print('RECORD1')
    print(hs.heap_chunks)
    print('RECORD2')
    hs.record = record2
    print(hs.heap_chunks)
    diff_result = heapdiff(record1, record2)
    for diff_one in diff_result['heap_chunks']:
        print('chunk at {:#x}: {} {}'.format(
            diff_one[0]._addr,
            diff_one[1]['type'],
            diff_one[1]['info']))
    print('RECORD3')
    hs.record = record3
    print(hs.heap_chunks)
    diff_result = heapdiff(record2, record3)
    for diff_one in diff_result['heap_chunks']:
        print('chunk at {:#x}: {} {}'.format(
            diff_one[0]._addr,
            diff_one[1]['type'],
            diff_one[1]['info']))
    

if __name__ == '__main__':
    binary = './diff'
    testcases = [
        '../libs/libc-2.23/',
        '../libs/libc-2.27/']

    binary32 = abspath(binary+'32')
    for case in testcases:
        dirname = os.path.join(abspath(case), '32bit')
        p = create_process(dirname, binary32)
        test(p)
        raw_input('press enter')
        p.terminate()


    
    binary64 = abspath(binary+'64')
    for case in testcases:
        dirname = os.path.join(abspath(case), '64bit')
        p = create_process(dirname, binary64)
        test(p)
        raw_input('press enter')
        p.terminate()