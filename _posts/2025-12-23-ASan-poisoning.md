---
title: "Analyzing github Pulls. What is Asan poisoning?"
date: 2025-12-23 12:00:00
categories: [QA, Open-Source]
tags: [white-box, testing, software, QA, coding, programming, debugging, source, code, github, analysis]
---
I was looking at the closed pull requests of a project I am analyzing (here is the github link for the [issue](https://github.com/facebook/zstd/pull/3451)) when I saw this change in the code and couldn't figure out what it is at first, so I decided to dive deeper to learn more about it. 

Original:

```c

if (alloc) {
	alloc = (BYTE *)alloc + ZSTD_CWKSP_ASAN_REDZONE_SIZE;
	if (ws->isStatic == ZSTD_cwksp_dynamic_alloc) {
		__asan_unpoison_memory_region(alloc, bytes); 
	}
}
#endif

```

Changed:

```c

if (alloc) {
alloc = (BYTE *)alloc + ZSTD_CWKSP_ASAN_REDZONE_SIZE;

	if (ws->isStatic == ZSTD_cwksp_dynamic_alloc) {
	__asan_unpoison_memory_region(alloc, bytes - 2 * ZSTD_CWKSP_ASAN_REDZONE_SIZE);
	}
}
#endif

```

I was looking at this change and asked myself: what the actual *fuck* is AddressSanitizer poisoning:

**AddressSanitizer (ASan),** is a fast and reliable memory error detector built into modern compilers like GCC and Clang, It can detect vulnerabilities like:

- **Heap buffer overflows**: Occur when a program writes outside the bounds of memory allocated on the heap using `malloc`, `calloc`, or `new`.
- **Stack buffer overflows**: Happen when a program writes past the end (or before the beginning) of a local array on the stack.
- **Global buffer overflows**: Triggered when accessing memory outside the bounds of a global or static array.
- **Use-after-free errors**: Occur when a program continues to access memory after it has been deallocated (freed).
- **Use-after-scope errors**: Happen when a program accesses a local variable outside of its lifetime, such as returning a pointer to a local stack variable.
- **Double-free and invalid free errors**: Detected when memory is freed more than once, or when a pointer that wasn’t allocated by a memory allocation function is passed to `free`.
- **Memory leaks**: While ASan alone doesn’t detect leaks, it can be combined with **LeakSanitizer** to report memory that was allocated but never freed.

We will talk about these vulnerabilities more in my other blog posts where we will be doing pwning ctf challanges and all that stuff.

I found this small piece of code on stackoverflow to showcase a demonstration of this issue:

In this piece of code we allocate memory for 10 integers on the heap and then we use the ASAN_POISON_MEMORY_REGION to poison data from data[5] to data[9] causing user-after-poisoning.

```cpp
#include <sanitizer/asan_interface.h>
int main() {
int* data = new int[10];
// poisoning from data[5] to data[9]
ASAN_POISON_MEMORY_REGION(data+5, sizeof(int)*5);
for (int i=0; i<=5; ++i) {
data[i] = i;
}}
```

compiling:

```bash
g++ -fsanitize=address -g Asan.C -o asan
```

we got these results:
```bash
==765==ERROR: AddressSanitizer: use-after-poison on address 0x79c2753e0024 at pc 0x5f12407ab1f9 bp 0x7fff01a44490 sp 0x7fff01a44480
WRITE of size 4 at 0x79c2753e0024 thread T0
    #0 0x5f12407ab1f8 in main /home/acid/src/Asan.C:9
    #1 0x7d827602c974 in __libc_start_call_main (/usr/lib/x86_64-linux-gnu/libc.so.6+0x2b974) (BuildId: 8c85e6f3065a22eb21e1ade2ab17a3567730db23)
    #2 0x7d827602ca27 in __libc_start_main (/usr/lib/x86_64-linux-gnu/libc.so.6+0x2ba27) (BuildId: 8c85e6f3065a22eb21e1ade2ab17a3567730db23)
    #3 0x5f12407ab0b4 in _start ../sysdeps/x86_64/start.S:115

0x79c2753e0024 is located 20 bytes inside of 40-byte region [0x79c2753e0010,0x79c2753e0038)
allocated by thread T0 here:
    #0 0x7d8276727b8b in operator new[](unsigned long) (/usr/lib/x86_64-linux-gnu/libasan.so.8+0x127b8b) (BuildId: e63c5e70347031d1fbf0669930fb561e0a66aa0a)
    #1 0x5f12407ab18a in main /home/acid/src/Asan.C:3
    #2 0x7d827602c974 in __libc_start_call_main (/usr/lib/x86_64-linux-gnu/libc.so.6+0x2b974) (BuildId: 8c85e6f3065a22eb21e1ade2ab17a3567730db23)
    #3 0x7d827602ca27 in __libc_start_main (/usr/lib/x86_64-linux-gnu/libc.so.6+0x2ba27) (BuildId: 8c85e6f3065a22eb21e1ade2ab17a3567730db23)
    #4 0x5f12407ab0b4 in _start ../sysdeps/x86_64/start.S:115

SUMMARY: AddressSanitizer: use-after-poison /home/acid/src/Asan.C:9 in main
Shadow bytes around the buggy address:
  0x79c2753dfd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x79c2753dfe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x79c2753dfe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x79c2753dff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x79c2753dff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x79c2753e0000: fa fa 00 00[04]f7 f7 fa fa fa fa fa fa fa fa fa
  0x79c2753e0080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x79c2753e0100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x79c2753e0180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x79c2753e0200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x79c2753e0280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==765==ABORTING
```

From this we can understand that we detected a use-after-poison error, primarily caused because the use of the `new` function.
The invalid access occurred at address `0x79c2753e0024`, which corresponds to `data[5]`, located within the poisoned memory region `[0x79c2753e0024, 0x79c2753e0038)`.
#### Resources I have read in the making of this blog post:
- [Detecting C/C++ memory bugs with ASan](https://can-ozkan.medium.com/detecting-c-and-c-memory-bugs-with-addresssanitizer-asan-84a9354716b7)
- [How to use ASAN_POISON_MEMORY_REGION](https://stackoverflow.com/questions/63107632/how-to-use-poisoning-function-of-address-sanitizer-with-asan-poison-memory-regio)
