# Modern Binary Exploitation - lab2B
 
| | |
| --- | --- |
| **Lab** | 02 · Memory Corruption |
| **Tier** | B |
| **Target** | `/levels/lab02/lab2B` |
| **Class** | 	stack buffer overflow (saved return-address overwrite) |
| **Goal** | recover the password for `lab2A` and escalate |


## Overview

An unbounded `strcpy` in `print_name` overflows a small stack buffer, and this time there is no adjacent flag to flip. We overflow far enough to overwrite the saved return address, and point it at a `shell()` function that is present in the binary but never called on any normal path. Because `shell` passes its argument to `system`, we also supply a pointer to a `/bin/sh` string, so returning into it spawns a shell.

## First look

Logged in as `lab2B` (via the password recovered from `lab2C`), read the target's permissions:

![](./img/ls_lab2B.png)

As with the earlier tiers, the binary is `setuid` and owned by the next user up, `lab2A`.
 
Before reading any code, check the mitigation posture with `checksec`.

![](./img/checksec_2B.png)

Run it blind to see the surface:

![](./img/running_lab2B.png)

With no argument it prints a usage line, and with one it echoes it back as `Hello <arg>`. So the input vector is a single command-line argument, and the program copies it somewhere before printing it. The copy is what we look at next.

## Disassembling `main`

Loading the binary in GDB and disassembling `main` shows that it does almost nothing itself. It checks the argument count, then hands `argv[1]` to a helper function called `print_name`. There is no buffer, no check, and no `shell()` call here, so whatever makes this challenge exploitable lives in `print_name`.

![](./img/disassemble_main_2B.png)

The relevant block:

```asm
0x08048706 <+9>:   cmp    DWORD PTR [ebp+0x8],0x2       ; argc == 2 ?
0x0804870a <+13>:  je     0x8048728 <main+43>           ; yes -> continue
0x0804870c <+15>:  mov    eax,DWORD PTR [ebp+0xc]        ; argv            (argc != 2 path)
0x0804870f <+18>:  mov    eax,DWORD PTR [eax]            ; argv[0]
0x08048715 <+24>:  mov    DWORD PTR [esp],0x80487e2       ; usage format string
0x0804871c <+31>:  call   0x8048570 <printf@plt>        ; print usage
0x08048721 <+36>:  mov    eax,0x1                        ; return 1 and exit
0x08048726 <+41>:  jmp    0x804873d <main+64>
 
0x08048728 <+43>:  mov    eax,DWORD PTR [ebp+0xc]        ; argv
0x0804872b <+46>:  add    eax,0x4                         ; &argv[1]
0x0804872e <+49>:  mov    eax,DWORD PTR [eax]            ; argv[1]
0x08048730 <+51>:  mov    DWORD PTR [esp],eax           ; print_name arg = argv[1]
0x08048733 <+54>:  call   0x80486d0 <print_name>        ; print_name(argv[1])
```

`main` requires exactly one argument (`argc == 2`) and passes `argv[1]` straight to `print_name`. Everything that matters happens inside that call, so we follow it.

## Disassembling `print_name`

![](./img/disassemble_print_name_2B.png)
