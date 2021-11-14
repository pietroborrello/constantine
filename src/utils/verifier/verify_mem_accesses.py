#!/usr/bin/env python3

import re
import sys
from intervaltree import IntervalTree, Interval
from collections import defaultdict
from colors import red, yellow

DFL_STRIDE = 0x40
DFL_MASK      = ~(DFL_STRIDE-1) & 0xffffffffffffffff

address_to_hits = defaultdict(int)
mem_accesses = open(sys.argv[1], 'r').read()
dfl_debug = open(sys.argv[2], 'r').read()

print(dfl_debug)

# interval tree to query all the accesses
# keeps track of which intervals are valid objects for range queries
# interval -> set(objs)
obj_interval_tree = IntervalTree()

# all the instruction that access the address (DFL_STRIDE aligned), with the hit count dict
# address -> instruction -> hits
mem_access_to_instruction = defaultdict(dict)

# keep for each instruction which addresses accessed and how much
# instruction -> address -> hits
instr_to_addresses = defaultdict(dict)

# parse all the dfl objects
matches = re.findall(r"DFL OBJ - aligned ptr: ([xa-fA-F0-9]+) - obj: ([xa-fA-F0-9]+) - size: ([0-9]+)", dfl_debug)
for aligned_ptr, obj, size in matches:
    aligned_ptr = int(aligned_ptr, 16)
    obj         = int(obj, 16)
    size        = int(size)

    # add the object to the interval tree
    # the library already manages duplicates
    obj_interval_tree[aligned_ptr : aligned_ptr + size] = obj

print(obj_interval_tree)
# exit()

# parse all the accesses addresses
matches = list(re.findall(r"([xa-fA-F0-9]+) -> ([xa-fA-F0-9]+) \[([0-9]+)\]", mem_accesses))
for instruction, address, hits in matches:
    instruction = int(instruction, 16)
    address = int(address, 16) & DFL_MASK
    hits    = int(hits)

    # ignore library code
    if instruction > 0x7f0000000000:
        continue

    # track only access related to dfl objects
    if not obj_interval_tree[address]:
        continue

    address_to_hits[address] += hits
    if instruction not in mem_access_to_instruction[address]:
        mem_access_to_instruction[address][instruction] = 0
    if address not in instr_to_addresses[instruction]:
        instr_to_addresses[instruction][address] = 0

    mem_access_to_instruction[address][instruction] += hits
    instr_to_addresses[instruction][address] += hits

for address in sorted(address_to_hits):
    hits = address_to_hits[address]
    print(f'0x{address:x}: {hits}')

incorrect = 0

# check for every obj interval that the access count is the same
# this check fails if more objects share the same cache line
# this check fails for heap/stack variables, but be best effort
for interval in obj_interval_tree:
    begin = interval.begin
    end   = interval.end
    data   = interval.data

    access_addresses = list(range(begin, end, DFL_STRIDE))
    accesses_counts  = [address_to_hits[addr] for addr in access_addresses]

    # check if all cache lines are accessed equally
    if not len(set(accesses_counts)) == 1:
        incorrect = 1
        print(yellow(f'WARNING mismatch for: 0x{begin:x} - 0x{end:x} -> obj: 0x{data:x}'))
        for addr in access_addresses:
            print(yellow(f'0x{addr:x} accessed by:'))
            for instruction in sorted(mem_access_to_instruction[addr]):
                hits = mem_access_to_instruction[addr][instruction]
                print(yellow(f'  0x{instruction:x} -> [{hits}]'))
        print(yellow('---------------------------'))

exit(incorrect)