from subprocess import Popen, PIPE
from HeapInspect import *

def create_process(path):
    p = Popen(path, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return p

def testcase(path):
    print('testcase '+path)
    p = create_process(path)
    pid = p.pid
    hi = HeapInspector(pid)
    hs = HeapShower(hi)
    return hs

if __name__ == 'main':
    cases = ['./fastbins', './bins']
    hs = testcase('./fastbins')
    print(hs.fastbins)
    print(hs.tcache_chunks)

    hs = testcase('./bins')
    print(hs.unsortedbins)
    print(hs.smallbins)
    print(hs.largebins)