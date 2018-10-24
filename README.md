# HeapInspect

Dynamically Inspect Heap In Python.

Core concept is to inspect heap by a given pid. 
**NO PTRACE, NO GDB, NO NEED OF LIBC**. 
Future use can falls in heap check and pwn exploration.

However, I'm starting to work on it. Code is ugly, functions are not complete.

# Useage

This is an early access view!

```raw
heapinspect $ python test.py 12408

==============================     heapchunks     ==============================
chunk(0x55fa6d3a2000 ): prev_size=0x0      size=0x251    fd=0x3             bk=0x0
chunk(0x55fa6d3a2250 ): prev_size=0x0      size=0x21     fd=0x0             bk=0x0
chunk(0x55fa6d3a2270 ): prev_size=0x0      size=0x21     fd=0x55fa6d3a2260  bk=0x0
chunk(0x55fa6d3a2290 ): prev_size=0x0      size=0x21     fd=0x55fa6d3a2280  bk=0x0
chunk(0x55fa6d3a22b0 ): prev_size=0x0      size=0x21     fd=0x55fa6d3a22a0  bk=0x0
chunk(0x55fa6d3a22d0 ): prev_size=0x0      size=0x21     fd=0x55fa6d3a22c0  bk=0x0
chunk(0x55fa6d3a22f0 ): prev_size=0x0      size=0x21     fd=0x55fa6d3a22e0  bk=0x0
chunk(0x55fa6d3a2310 ): prev_size=0x0      size=0x21     fd=0x55fa6d3a2300  bk=0x0
chunk(0x55fa6d3a2330 ): prev_size=0x0      size=0x411    fd=0x7f54b9684330  bk=0x7f54b9684330
chunk(0x55fa6d3a2740 ): prev_size=0x7f54b9683ca0 size=0x1b11   fd=0x7f54b9683ca0  bk=0x7f54b9683ca0
chunk(0x55fa6d3a4250 ): prev_size=0x1b10   size=0x20     fd=0x0             bk=0x0
chunk(0x55fa6d3a4270 ): prev_size=0x0      size=0x1ed91  fd=0x0             bk=0x0
==============================    unsortedbins    ==============================
chunk(0x55fa6d3a2740 ): prev_size=0x7f54b9683ca0 size=0x1b11   fd=0x7f54b9683ca0  bk=0x7f54b9683ca0
==============================      bins 0x0      ==============================
chunk(0x55fa6d3a2740 ): prev_size=0x7f54b9683ca0 size=0x1b11   fd=0x7f54b9683ca0  bk=0x7f54b9683ca0
==============================    tcache 0x20     ==============================
chunk(0x55fa6d3a2290 ): prev_size=0x0      size=0x21     fd=0x55fa6d3a2280  bk=0x0
chunk(0x55fa6d3a2270 ): prev_size=0x0      size=0x21     fd=0x55fa6d3a2260  bk=0x0
chunk(0x55fa6d3a2250 ): prev_size=0x0      size=0x21     fd=0x0             bk=0x0

```

Oh, I forgot to mention that I'm developing it in `libc-2.27`. Other libc support will be add on after I finished the framework.

# Devlog

2018/10/24 version 0.04

- `HeapRecoder` , I will make a heapdiff
- `smallbins` and `largebins`

2018/10/23 version 0.0.3

- `fastbin` prototype
- `unsortedbin` prototype
- `bins` prototype
- `tcache` prototype

2018/10/22 version 0.0.2

- add `C_Struct` to handle c structure

2018/10/19 version 0.0.1

- add `class HeapInspector`
- trying to parse more information of `arena`

2018/10/18 version 0.0.0

- add `class Proc` in `proc_util`
- experimental test in `test.py`