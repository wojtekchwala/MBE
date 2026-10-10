# Modern Binary Exploitation - lab1B

| | |
| --- | --- |
| **Tier** | B |
| **Target** | `/levels/lab01/lab1B` |
| **Class** | reversible obfuscation (XOR "encryption") |
| **Goal** | recover the password for `lab1A` and escalate |

## Overview

In this challenge the password is not stored in the binary but derived from one. Our input is subtracted from a hardcoded secret to produce a key, and that key is used to XOR-decrypt an embedded string. The win branch fires only when the decrypted string equals "Congratulations!". Because XOR is reversible and both the ciphertext and the target plaintext are in the binary, we recover the key from a single byte, work backward to the required input, and escalate to lab1A.

## First look

Logged in as `lab1B` (via the password recovered from lab1C), read the permissions of the next target:

![](./img/ls_lab1B.png)

As with lab1C, the setuid bit is set and the owner is the next user up, `lab1A`. Running the binary therefore executes as `lab1A`, so beating it yields a shell as `lab1A` and read access to `lab1A`'s `.pass`.

Run it blind to see the surface. Like lab1C, it prints a banner and asks for a password, reading a single value from us:
```
$ ./lab1B
.---------------------------.
|-- RPISEC - CrackMe v2.0 --|
'---------------------------'

Password:
```

## Disassembling `main`

We load the binary in GDB and disassemble main. Unlike `lab1C`, the logic does not stay in one function. `main` only reads our input and hands it off, so we follow the calls it makes into `test` and then `decrypt`, where the real check lives.

![](./img/disassemble_main_1B.png)

The relevant block (Intel syntax):

```asm
0x08048bfd <+25>:  call   time@plt            ; time(NULL)
0x08048c05 <+33>:  call   srand@plt           ; srand(time(NULL))  seeds the RNG
...                                            ; banner + "Password: " prompt (puts/printf)
0x08048c3a <+86>:  lea    eax,[esp+0x1c]       ; eax = &input
0x08048c3e <+90>:  mov    [esp+0x4],eax        ; scanf arg2 = &input
0x08048c42 <+94>:  mov    [esp],0x8048dee      ; scanf arg1 = format string ptr
0x08048c49 <+101>: call   __isoc99_scanf       ; scanf("%d", &input)
0x08048c4e <+106>: mov    eax,[esp+0x1c]       ; eax = input
0x08048c52 <+110>: mov    [esp+0x4],0x1337d00d ; test arg2 = secret
0x08048c5a <+118>: mov    [esp],eax            ; test arg1 = input
0x08048c5d <+121>: call   test                 ; test(input, 0x1337d00d)
```

Shows scanf("%d", &input) then test(input, 0x1337d00d). Confirm the format string that main passes to scanf:
