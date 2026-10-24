# Modern Binary Exploitation - lab3B
 
| | |
| --- | --- |
| **Lab** | 03 · Shellcoding |
| **Tier** | B |
| **Target** | `/levels/lab03/lab3B` (ELF32, Intel 80386, non-PIE) |
| **Class** | Stack-based buffer overflow (unbounded `gets`) |
| **Root cause** | `gets` reads attacker input into a 128-byte stack buffer with no length bound |
| **Impact** | 	Saved return-address overwrite → arbitrary code execution as `lab3A` |
| **Goal** | 	run injected shellcode as the setuid owner and retrieve the `.pass` for `lab3A` |
| **Difficulty** | Low (no stack canary, NX, PIE, or ASLR) |

## Overview

## First look

Logged in as `lab3B`, the first thing we look at is the target's permissions:

![](./img/ls_lab3B.png)

The s in the mode string `-r-sr-x---` is the `setuid` bit, and the owner is `lab3A`, so any code the program runs executes with `lab3B`'s effective `uid`.

We check the mitigation posture with checksec:

![](./img/checksec_3B.png)

All protections are disabled. With `NX` off, the stack and other writable mappings are executable, so attacker-supplied bytes can be executed as code. With no `stack canary`, a sequential write from the buffer reaches the saved return address with no guard value in between, so hijacking control flow requires only the buffer-to-return offset. With `PIE` disabled, the binary loads at a fixed base, so its code and data addresses are constant across runs. With `RELRO` off, the `GOT` stays writable, and with `FORTIFY` off, the standard string functions carry no bounds-checking wrappers.

Running it blind shows the surface:

```bash
lab3B@warzone:/levels/lab03$ ./lab3B
just give me some shellcode, k
test
child is exiting...
```

## Disassembling `main`

`main` calls `fork`, splitting the process into a parent and a child that run different code. The child reads our input with `gets`. The parent monitors the child and kills it if it tries to run `execve`.

![](./img/disassemble_main_3B.png)

```asm
0x0804899d <+14>:  call   fork@plt
0x080489a2 <+19>:  mov    DWORD PTR [esp+0xac],eax     ; save the fork() return
0x080489d0 <+65>:  cmp    DWORD PTR [esp+0xac],0x0
0x080489d8 <+73>:  jne    main+160                     ; parent -> +160, child falls through
```
 
`fork` returns `0` in the child and the child's pid in the parent, so the child takes the `+75` path and the parent takes `+160`.


