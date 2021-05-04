import argparse
from heapinspect.core import *
from pandare import Panda

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='HeapInspect.py',
        description='''Inspect your heap by a given pid.
Author:lacraig2 (forked from matrix1001)
Github:https://github.com/lacraig2/pandaheapinspect (forked from https://github.com/matrix1001/heapinspect)''')
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
        '-x',
        action='store_false',
        help='''ignore: heapchunks'''
        )

    args = parser.parse_args()

    panda = Panda(generic="x86_64")

    @panda.hook_symbol("libc","malloc")
    def hook(cpu, tb, h):
        print(f"Caught libc:malloc in {panda.get_process_name(cpu)}")
        try:
            global pid, args
            arena_info = {"main_arena_offset": 4111432,"tcache_enable": True}
            hi = HeapInspector(0,panda=panda,arena_info=arena_info)
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
        except Exception as e:
            raise e
        h.enabled = False
        panda.end_analysis()




    @panda.queue_async
    def runner():
        panda.revert_sync("root")
        panda.run_serial_cmd("ls -la && sleep 10")
        panda.end_analysis()


    panda.run()

