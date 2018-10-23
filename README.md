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
chunk(0x555555559000 ): prev_size=0x0      size=0x251    fd=0x3             bk=0x0
chunk(0x555555559250 ): prev_size=0x0      size=0x21     fd=0x0             bk=0x0
chunk(0x555555559270 ): prev_size=0x0      size=0x21     fd=0x555555559260  bk=0x0
chunk(0x555555559290 ): prev_size=0x0      size=0x21     fd=0x555555559280  bk=0x0
chunk(0x5555555592b0 ): prev_size=0x0      size=0x21     fd=0x5555555592a0  bk=0x0
chunk(0x5555555592d0 ): prev_size=0x0      size=0x21     fd=0x5555555592c0  bk=0x0
chunk(0x5555555592f0 ): prev_size=0x0      size=0x21     fd=0x5555555592e0  bk=0x0
chunk(0x555555559310 ): prev_size=0x0      size=0x21     fd=0x555555559300  bk=0x0
chunk(0x555555559330 ): prev_size=0x0      size=0x1f21   fd=0x7ffff7fa5ca0  bk=0x7ffff7fa5ca0
chunk(0x55555555b250 ): prev_size=0x1f20   size=0x20     fd=0x0             bk=0x0
chunk(0x55555555b270 ): prev_size=0x0      size=0x1ed91  fd=0x0             bk=0x0
==============================    unsortedbins    ==============================
chunk(0x555555559330 ): prev_size=0x0      size=0x1f21   fd=0x7ffff7fa5ca0  bk=0x7ffff7fa5ca0
==============================      bins 0x0      ==============================
chunk(0x555555559330 ): prev_size=0x0      size=0x1f21   fd=0x7ffff7fa5ca0  bk=0x7ffff7fa5ca0
```

# Devlog

2018/10/23 version 0.0.3

- `fastbin` prototype
- `unsortedbin` prototype
- `bins` prototype

2018/10/22 version 0.0.2

- add `C_Struct` to handle c structure

2018/10/19 version 0.0.1

- add `class HeapInspector`
- trying to parse more information of `arena`

2018/10/18 version 0.0.0

- add `class Proc` in `proc_util`
- experimental test in `test.py`