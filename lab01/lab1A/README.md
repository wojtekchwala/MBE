# Modern Binary Exploitation - lab1A
 
| | |
| --- | --- |
| **Tier** | A (hardest) |
| **Target** | `/levels/lab01/lab1A` |
| **Class** | username-derived serial check + `ptrace` anti-debug |
| **Goal** | recover a valid serial and escalate |

 ## Overview
 
One or two sentences: the serial is derived from the username by a checksum, and an anti-debug check guards the routine. We defeat the anti-debug, read the checksum the program computes, and feed it back as the serial.

## First look
 
Logged in as `lab1A` (via the password recovered from lab1B), read the permissions of the final lab01 target:

![](./img/ls_lab1A.png)
