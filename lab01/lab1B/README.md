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
