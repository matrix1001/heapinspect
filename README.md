# HeapInspect

Dynamically Inspect Heap In Python.

Core concept is to inspect heap by a given pid. 
**NO PTRACE, NO GDB, NO NEED OF LIBC**. 
Future use can falls in heap check and pwn exploration.

However I'm starting to work on it. Code is ugly, functions are not complete.

# Devlog

2018/10/19 version 0.0.1

- add `class HeapInspector`
- trying to parse more information of `arena`

2018/10/18 version 0.0.0

- add `class Proc` in `proc_util`
- experimental test in `test.py`