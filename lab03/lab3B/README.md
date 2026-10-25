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

The child path sets up the trace relationship, prints the banner, and reads our line:

```asm
0x08048a0d <+126>: call   ptrace@plt                   ; ptrace(PTRACE_TRACEME, 0, 0, 0)
0x08048a12 <+131>: mov    DWORD PTR [esp],0x8048b84    ; "just give me some shellcode, k"
0x08048a19 <+138>: call   puts@plt
0x08048a1e <+143>: lea    eax,[esp+0x20]               ; &buf
0x08048a22 <+147>: mov    DWORD PTR [esp],eax
0x08048a25 <+150>: call   gets@plt                     ; gets(buf), unbounded read, the bug
0x08048a2a <+155>: jmp    main+339                     ; fall to the shared epilogue and return
```

The constant moved into the puts argument slot at +131 is a pointer, not the text itself. Resolving it as a string shows the banner we already saw on the blind run:

`ptrace(PTRACE_TRACEME)` asks the parent to become the child's tracer. The buffer sits at `[esp+0x20]`, it is 128 bytes, and `gets` writes into it with no length. The read ends only at a newline, so everything we send up to that newline lands in the frame, past the buffer and over the saved return address. The child then jumps to the shared epilogue and returns through the address we now control.

![](./img/puts_string_3B.png)

So `+131` and `+138` together are `puts("just give me some shellcode, k")`. The `mov` loads the argument at `[esp]`, which is where the 32-bit cdecl convention passes the first argument, and the `call` consumes it. The same reading applies to `+143` through `+150`. `lea eax,[esp+0x20]` computes the address of the 128-byte input buffer, the `mov` places that address in the argument slot, and `gets` reads into it. `ptrace(PTRACE_TRACEME)` above them asks the parent to become the child's tracer. `gets` takes no length, so the read ends only at a newline, and everything we send up to that newline lands in the frame, past the buffer and over the saved return address. The child then jumps to the shared epilogue and returns through the address we now control.
 
The parent path is a watch loop. It waits for the child to change state, and the status word decides what happens next:
