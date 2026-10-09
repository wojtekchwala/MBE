# Modern Binary Exploitation - lab1C

| | |
| --- | --- |
| **Tier** | C (entry) |
| **Target** | `/levels/lab01/lab1C` |
| **Class** | hardcoded credential / compiled-in secret |
| **Goal** | recover the password for `lab1B` and escalate |

## Overview
 
In this challenge we exploit a SUID binary that guards a privileged action behind a comparison against a value left in the code. We disassemble the binary to recover the expected value and the command it runs, supply that value to reach the privileged branch, and escalate to lab1B.

## First look
 
The target is a 32-bit x86 ELF. Before disassembling anything, the first thing to read is the **file permissions**, because they define the trust boundary — who may run the binary and whose privileges it runs with:


