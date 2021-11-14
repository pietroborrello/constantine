#!/usr/bin/env python3

import sys
from subprocess import check_output
input = sys.argv[1]

all_cycles = []
for _ in range(1000):
    out = check_output("LD_DEBUG=statistics %s < /dev/zero 2>&1 1>/dev/null | grep total | cut -d: -f3 | cut -d' ' -f 2" % input, shell=True)
    cycles = int(out)
    all_cycles.append(cycles)

print(sum(all_cycles) / len(all_cycles))