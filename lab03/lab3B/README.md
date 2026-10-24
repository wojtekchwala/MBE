# Modern Binary Exploitation - lab3B
 
| | |
| --- | --- |
| **Lab** | 03 · Shellcoding |
| **Tier** | B |
| **Target** | `/levels/lab03/lab3B` (ELF32, Intel 80386, non-PIE) |
| **Class** |  |
| **Root cause** |  |
| **Impact** |  |
| **Goal** |  |
| **Difficulty** | Low (no stack canary, NX, PIE, or ASLR) |

## Overview

## First look

Logged in as `lab3B`, the first thing we look at is the target's permissions:



Running it blind shows the surface:

```bash
lab3B@warzone:/levels/lab03$ ./lab3B
just give me some shellcode, k
test
child is exiting...
```
