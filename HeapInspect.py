import argparse
from heapinspect import *


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='HeapInspect.py',
        description='''Inspect your heap by a given pid.
Author:matrix1001
Github:https://github.com/matrix1001/heapinspect''')
    parser.add_argument(
        '--raw',
        action='store_true',
        help='show more detailed chunk info'
        )
    parser.add_argument(
        '--rela',
        action='store_true',
        help='show relative detailed chunk info'
        )
    parser.add_argument(
        'pid',
        type=int,
        help='pid of the process'
        )
    parser.add_argument(
        '-x',
        action='store_false',
        help='''ignore: heapchunks'''
        )

    args = parser.parse_args()
    pid = args.pid
    hi = HeapInspector(pid)
    if args.rela:
        hs = HeapShower(hi)
        hs.relative = True
        if args.x:
            print(hs.heap_chunks)
        print(hs.fastbins)
        print(hs.unsortedbins)
        print(hs.smallbins)
        print(hs.largebins)
        print(hs.tcache_chunks)
    elif args.raw:
        hs = HeapShower(hi)
        if args.x:
            print(hs.heap_chunks)
        print(hs.fastbins)
        print(hs.unsortedbins)
        print(hs.smallbins)
        print(hs.largebins)
        print(hs.tcache_chunks)
    else:
        pp = PrettyPrinter(hi)
        print(pp.all)
