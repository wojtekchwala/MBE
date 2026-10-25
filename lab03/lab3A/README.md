# Modern Binary Exploitation - lab3A
 
| | |
| --- | --- |
| **Lab** | 03 · Shellcoding |
| **Tier** | A |
| **Target** | `/levels/lab03/lab3A` (ELF32, Intel 80386) |
| **Class** |  |
| **Root cause** | |
| **Impact** |  |
| **Goal** | run shellcode as the setuid owner and retrieve the next `.pass` |
| **Difficulty** | |

## Overview

## First look
 
Logged in as `lab3A`, the first thing we look at is the target's permissions:
 
![](./img/ls_lab3A.png)

The `s` in the mode string `-r-sr-x---` is the `setuid` bit, and the owner is `lab3end`, so any code the program runs executes with `lab3end`'s effective `uid`. The group is `lab3A`, which is why we, logged in as `lab3A`, hold the group's `r-x` and may execute the file at all. The escalation target for this tier is therefore `lab3end`, and the file we are after is `/home/lab3end/.pass`.

We check the mitigation posture with checksec:

![](./img/checksec_3A.png)


All protections are disabled. With `NX` off, the stack and other writable mappings are executable, so attacker-supplied bytes can be executed as code. With no `stack canary`, a sequential write from the buffer reaches the saved return address with no guard value in between, so hijacking control flow requires only the buffer-to-return offset. With `PIE` disabled, the binary loads at a fixed base, so its code and data addresses are constant across runs. With `RELRO` off, the `GOT` stays writable, and with `FORTIFY` off, the standard string functions carry no bounds-checking wrappers.

Running it blind shows the surface:

```bash
$ ./lab3A
----------------------------------------------------
  Welcome to quend's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   quend has reserved some storage for herself :>
----------------------------------------------------

Input command: read
 Index: 1
 Number at data[1] is 0
 Completed read command successfully
```

## Disassembling `main`

`main` reserves a large frame and zeroes a data array near the bottom of it:

![](./img/disassemble_main_3A.png)

```asm
0x08048a17 <+5>:   and    esp,0xfffffff0
0x08048a1a <+8>:   sub    esp,0x1c0                 ; reserve the frame
0x08048a62 <+80>:  lea    ebx,[esp+0x18]            ; &data
0x08048a6b <+89>:  mov    edx,0x64                  ; 0x64 = 100 dwords
0x08048a74 <+98>:  rep stos DWORD PTR es:[edi],eax  ; zero data[0..99], eax = 0
```

The `rep stos` writes `0x64` (100) zero dwords starting at `[esp+0x18]`, so `data` is a 100-entry array of 4-byte integers, 400 bytes, living on the stack.

Before it serves a single command, `main` scrubs the process arguments and environment. It walks `argv` and then `envp` and zeroes every string it finds:

```asm
; walk argv at [ebp+0xc], zero each string
0x08048a80 <+110>: call   strlen@plt
0x08048a99 <+135>: call   memset@plt               ; memset(argv[i], 0, len)
; then the same walk over envp at [ebp+0x10]
0x08048ace <+188>: call   memset@plt               ; memset(envp[i], 0, len)
```

This is deliberate hardening, and it is worth naming because it removes an avenue the earlier tiers left open. Stashing a shellcode stub in an environment variable and returning to it is a standard move, and `main` closes it by overwriting `argv` and `envp` with zeroes at startup. Whatever code this exploit injects has to live somewhere `main` does not scrub.

The rest of `main` is a command loop. It reads a command, compares it against three keywords, and dispatches:

```asm
0x08048b14 <+258>: lea    eax,[esp+0x1a8]
0x08048b1e <+268>: call   fgets@plt                 ; fgets(cmd, 0x14, stdin), 20 bytes
0x08048b57 <+325>: call   strncmp@plt               ; compare against "store"
0x08048b5e <+332>: jne    main+355
0x08048b60 <+334>: lea    eax,[esp+0x18]            ; &data
0x08048b67 <+341>: call   store_number             ; store_number(&data)
0x08048b9f <+397>: call   read_number              ; read_number(&data), on the "read" branch
```
