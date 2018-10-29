# HeapInspect

Dynamically Inspect Heap In Python.

Core concept is to inspect heap by a given pid. 
**NO PTRACE, NO GDB, NO NEED OF LIBC**. 
Future use can falls in heap check and pwn exploration.

However, I'm starting to work on it. Code is ugly and functions are not complete.

__Advantage over gdb plugins (like pwndbg)__

- No gdb needed. 
- No ptrace needed. Won't interrupt the process.
- Implemented in pure python. No other module needed.
- No symbols needed. (pwndbg need libc symbols to resolve `main_arena`)
- Easy to use API. (Working on it)
- Heap diff. (Working on it)
- blablabla......  

# Useage

__Now support multi glibc (tested on 2.23-2.27) and x86 binary.__


This is an early access view!

```raw
heapinspect $ python HeapInspect.py 12408

==============================     heapchunks     ==============================
chunk(0x555555559000): prev_size=0x0      size=0x251    fd=0x7             bk=0x0
chunk(0x555555559250): prev_size=0x0      size=0x21     fd=0x0             bk=0x0
chunk(0x555555559270): prev_size=0x0      size=0x21     fd=0x555555559260  bk=0x0
chunk(0x555555559290): prev_size=0x0      size=0x21     fd=0x555555559280  bk=0x0
chunk(0x5555555592b0): prev_size=0x0      size=0x21     fd=0x5555555592a0  bk=0x0
chunk(0x5555555592d0): prev_size=0x0      size=0x21     fd=0x5555555592c0  bk=0x0
chunk(0x5555555592f0): prev_size=0x0      size=0x21     fd=0x5555555592e0  bk=0x0
chunk(0x555555559310): prev_size=0x0      size=0x21     fd=0x555555559300  bk=0x0
chunk(0x555555559330): prev_size=0x0      size=0x411    fd=0x7ffff7fa6190  bk=0x555555559c50
chunk(0x555555559740): prev_size=0x5555.. size=0x401    fd=0x7ffff7fa5ca0  bk=0x7ffff7fa5ca0
chunk(0x555555559b40): prev_size=0x400    size=0x110    fd=0x7ffff7fa62f0  bk=0x7ffff7fa62f0
chunk(0x555555559c50): prev_size=0x0      size=0x821    fd=0x7ffff7fa6190  bk=0x55555555a580
chunk(0x55555555a470): prev_size=0x820    size=0x110    fd=0x7ffff7fa62a0  bk=0x7ffff7fa62a0
chunk(0x55555555a580): prev_size=0x5555.. size=0x831    fd=0x555555559c50  bk=0x7ffff7fa6190
chunk(0x55555555adb0): prev_size=0x830    size=0x110    fd=0x7ffff7fa60b0  bk=0x7ffff7fa60b0
chunk(0x55555555aec0): prev_size=0x5555.. size=0x211    fd=0x7ffff7fa6000  bk=0x7ffff7fa6000
chunk(0x55555555b0d0): prev_size=0x0      size=0x161    fd=0x7ffff7fa5df0  bk=0x7ffff7fa5df0
chunk(0x55555555b230): prev_size=0x160    size=0x20     fd=0x0             bk=0x0
chunk(0x55555555b250): prev_size=0x0      size=0x21     fd=0x7ffff7fa5cb0  bk=0x7ffff7fa5cb0
chunk(0x55555555b270): prev_size=0x20     size=0x20     fd=0x0             bk=0x0
chunk(0x55555555b290): prev_size=0x0      size=0x111    fd=0x0             bk=0x0
chunk(0x55555555b3a0): prev_size=0x0      size=0x1ec61  fd=0x0             bk=0x0
==============================    unsortedbins    ==============================
chunk(0x555555559740): prev_size=0x5555.. size=0x401    fd=0x7ffff7fa5ca0  bk=0x7ffff7fa5ca0
==============================  smallbins   0x20  ==============================
chunk(0x55555555b250): prev_size=0x0      size=0x21     fd=0x7ffff7fa5cb0  bk=0x7ffff7fa5cb0
==============================  smallbins   0x160 ==============================
chunk(0x55555555b0d0): prev_size=0x0      size=0x161    fd=0x7ffff7fa5df0  bk=0x7ffff7fa5df0
==============================  largebins   0x4f  ==============================
chunk(0x555555559c50): prev_size=0x0      size=0x821    fd=0x7ffff7fa6190  bk=0x55555555a580
chunk(0x55555555a580): prev_size=0x5555.. size=0x831    fd=0x555555559c50  bk=0x7ffff7fa6190

relative mode

=========================     relative heapchunks      =========================
chunk(heap+0x0     ): prev_size=0x0      size=0x251    fd=0x7           bk=0x0
chunk(heap+0x250   ): prev_size=0x0      size=0x21     fd=0x0           bk=0x0
chunk(heap+0x270   ): prev_size=0x0      size=0x21     fd=heap+0x260    bk=0x0
chunk(heap+0x290   ): prev_size=0x0      size=0x21     fd=heap+0x280    bk=0x0
chunk(heap+0x2b0   ): prev_size=0x0      size=0x21     fd=heap+0x2a0    bk=0x0
chunk(heap+0x2d0   ): prev_size=0x0      size=0x21     fd=heap+0x2c0    bk=0x0
chunk(heap+0x2f0   ): prev_size=0x0      size=0x21     fd=heap+0x2e0    bk=0x0
chunk(heap+0x310   ): prev_size=0x0      size=0x21     fd=heap+0x300    bk=0x0
chunk(heap+0x330   ): prev_size=0x0      size=0x411    fd=libc+0x1b8190 bk=heap+0xc50
chunk(heap+0x740   ): prev_size=0x5555.. size=0x401    fd=libc+0x1b7ca0 bk=libc+0x1b7ca0
chunk(heap+0xb40   ): prev_size=0x400    size=0x110    fd=libc+0x1b82f0 bk=libc+0x1b82f0
chunk(heap+0xc50   ): prev_size=0x0      size=0x821    fd=libc+0x1b8190 bk=heap+0x1580
chunk(heap+0x1470  ): prev_size=0x820    size=0x110    fd=libc+0x1b82a0 bk=libc+0x1b82a0
chunk(heap+0x1580  ): prev_size=0x5555.. size=0x831    fd=heap+0xc50    bk=libc+0x1b8190
chunk(heap+0x1db0  ): prev_size=0x830    size=0x110    fd=libc+0x1b80b0 bk=libc+0x1b80b0
chunk(heap+0x1ec0  ): prev_size=0x5555.. size=0x211    fd=libc+0x1b8000 bk=libc+0x1b8000
chunk(heap+0x20d0  ): prev_size=0x0      size=0x161    fd=libc+0x1b7df0 bk=libc+0x1b7df0
chunk(heap+0x2230  ): prev_size=0x160    size=0x20     fd=0x0           bk=0x0
chunk(heap+0x2250  ): prev_size=0x0      size=0x21     fd=libc+0x1b7cb0 bk=libc+0x1b7cb0
chunk(heap+0x2270  ): prev_size=0x20     size=0x20     fd=0x0           bk=0x0
chunk(heap+0x2290  ): prev_size=0x0      size=0x111    fd=0x0           bk=0x0
chunk(heap+0x23a0  ): prev_size=0x0      size=0x1ec61  fd=0x0           bk=0x0
=========================    relative unsortedbins     =========================
chunk(heap+0x740   ): prev_size=0x5555.. size=0x401    fd=libc+0x1b7ca0 bk=libc+0x1b7ca0
=========================  relative smallbins    0x20  =========================
chunk(heap+0x2250  ): prev_size=0x0      size=0x21     fd=libc+0x1b7cb0 bk=libc+0x1b7cb0
=========================  relative smallbins    0x160 =========================
chunk(heap+0x20d0  ): prev_size=0x0      size=0x161    fd=libc+0x1b7df0 bk=libc+0x1b7df0
=========================  relative largebins    0x4f  =========================
chunk(heap+0xc50   ): prev_size=0x0      size=0x821    fd=libc+0x1b8190 bk=heap+0x1580
chunk(heap+0x1580  ): prev_size=0x5555.. size=0x831    fd=heap+0xc50    bk=libc+0x1b8190


```


# Devlog

2018/10/29 version 0.0.7

- auto test
- code refine

2018/10/27 version 0.0.6

this is not a stable version. im trying to fix bugs due to different glibc. i need help to test this.

- add multi libc support
- add x86 support 

2018/10/26 version 0.0.5

next version will add multi libc support. heapdiff and heap check will be added later.

- `HeapShower`
- relative heap & libc offset showing
- fix search loop bug
- `bins` now search from `bk` instead of `fd`, as the manner of glibc

2018/10/24 version 0.0.4

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