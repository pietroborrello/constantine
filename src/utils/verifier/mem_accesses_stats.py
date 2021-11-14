#!/usr/bin/env python3

from os import lseek
import re
import sys
from intervaltree import IntervalTree, Interval
from collections import defaultdict
from colors import red, yellow
from pprint import pprint

DFL_STRIDE = 0x40
DFL_MASK      = ~(DFL_STRIDE-1) & 0xffffffffffffffff
DUMMY_OBJ = 0xeff000

address_to_hits = defaultdict(int)
dfl_debug = open(sys.argv[1], 'r').read()

class Obj:
    def __init__(self, address, size, orig_size):
        self.address   = address
        self.size      = size
        self.orig_size = orig_size
        self.access_count = 0
    
    def __eq__(self, other):
        # ignore the stealer_id
        return type(self) == type(other) and self.address == other.address
    
    def __ne__(self, other):
        """Overrides the default implementation (unnecessary in Python 3)"""
        return not self.__eq__(other)

    def __hash__(self):
        """Overrides the default implementation"""
        # ignore the stealer_id
        return hash(tuple((self.address)))

    def __str__(self) -> str:
        return f"obj: 0x{self.address:x} - size: {self.size} ({self.orig_size}) - access count: {self.access_count}"

# print(dfl_debug)

# object_address -> object
objects = dict()

# the set of objects accessed togheter for a pointer
ptr_to_objects = defaultdict(set)
ptr_access_count = defaultdict(int)

# parse all the dfl objects
matches = re.findall(r"DFL OBJ - aligned ptr: ([xa-fA-F0-9]+) - obj: ([xa-fA-F0-9]+) - size: ([0-9]+) - orig_size: ([0-9]+)", dfl_debug)
for aligned_ptr, obj, size, orig_size in matches:
    aligned_ptr = int(aligned_ptr, 16)
    obj         = int(obj, 16)
    size        = int(size)
    orig_size   = int(orig_size)

    # index the objects by their aligned pointer
    _object = Obj(obj, size, orig_size)

    assert(aligned_ptr not in objects)
    objects[obj] = _object

print("objects:", len(objects))
bytes_accessed = {"LOAD" : 0, "STORE" : 0}
sized_accesses = defaultdict(int)
last_obj  = None
last_ptr  = None
last_type = None

# parse all the accesses addresses for global load/stores
matches = list(re.findall(r"GLOB (LOAD|STORE): ([xa-fA-F0-9]+) - size: ([0-9]+) - ptr: ([xa-fA-F0-9]+)", dfl_debug))
for i, (access_type, obj_addr, size, ptr) in enumerate(matches):
    obj_addr = int(obj_addr, 16)
    ptr      = int(ptr, 16)
    size     = int(size)

    objects[obj_addr].access_count += 1
    ptr_to_objects[ptr].add(obj_addr)
    ptr_access_count[ptr] += size
    bytes_accessed[access_type] += size
    sized_accesses[size]+= 1
    if(last_obj == obj_addr and last_ptr == ptr and last_type == access_type and access_type != "STORE"):
        # print("DUPLICATE ACCESS!")
        # print(matches[i-1])
        # print(matches[i])
        # exit(123)
        pass
    last_obj  = obj_addr
    last_ptr  = ptr
    last_type = access_type

# for obj loads/store we cannot use regexes as we don't know how many objects there
# are in a head_list
lines = dfl_debug.split('\n')
next_idx = 0
while next_idx < len(lines):
    line = lines[next_idx]
    next_idx += 1
    if 'OBJ LOAD' not in line and 'OBJ STORE' not in line:
        continue
    match = re.match(r"OBJ (LOAD|STORE) - ptr: ([xa-fA-F0-9]+)", line)
    access_type, ptr = match.groups()
    ptr = int(ptr, 16)

    match = re.match(r"  obj: ([xa-fA-F0-9]+) - field_off: ([0-9]+) - size: ([0-9]+) \.+", lines[next_idx])
    while match:
        obj_addr, field_off, size = match.groups()
        # print(obj_addr)
        obj_addr = int(obj_addr, 16)
        size     = int(size)
        objects[obj_addr].access_count += 1
        ptr_to_objects[ptr].add(obj_addr)
        ptr_access_count[ptr] += size
        bytes_accessed[access_type] += size
        sized_accesses[size]+= 1
        next_idx += 1
        if(last_obj == obj_addr and last_ptr == ptr and last_type == access_type and access_type != "STORE"):
            # print("DUPLICATE ACCESS!")
            # print(lines[next_idx-1])
            # exit(123)
            pass
        last_obj  = obj_addr
        last_ptr  = ptr
        last_type = access_type
        match = re.match(r"  obj: ([xa-fA-F0-9]+) - field_off: ([0-9]+) - size: ([0-9]+) \.+", lines[next_idx])

# check for accesses without mathes
next_idx = 0
current_ptr = None
matched = False
while next_idx < len(lines):
    line = lines[next_idx]
    next_idx += 1
    if 'DFL OBJ - ' in line or 'DFL ADD - ' in line:
        continue
    if 'ptr: ' in line:
        ptr_accessed = int(line.split("ptr: ")[1].split(' ')[0], 16)
        if current_ptr is None:
            current_ptr = ptr_accessed
        elif ptr_accessed != current_ptr:
            if not matched and current_ptr != DUMMY_OBJ:
                print(f"NO MATCH - ptr: 0x{current_ptr:x} - line: {next_idx-1}")
                # exit(123)
            current_ptr = ptr_accessed
            matched = False
    if 'MATCH' in line and 'NO MATCH' not in line:
        matched = True


# compute the sets of objects accessed together
# set -> weight
sets_weights = defaultdict(int)
obj_sets = set()
for ptr, s in ptr_to_objects.items():
    s = frozenset(s)
    obj_sets.add(s)
    sets_weights[s] += ptr_access_count[ptr] 

print("Total weights:")
print(sum(sets_weights.values()))
print("Bytes Accessed: " + str(bytes_accessed))
print("Sized Accesses:")
pprint(sized_accesses)
# sort the object sets by the size*access_count of the objects
for obj_set in sorted(obj_sets, key = lambda s: sets_weights[s], reverse=True):
    print(f"---- {sets_weights[obj_set]} (set size: {len(obj_set)}) ----")
    for o in obj_set:
        print(objects[o])

# for obj in sorted(objects.values(), key = lambda o: o.size * o.access_count, reverse=True):
#     print(obj)
print("Total weights:")
print(sum(sets_weights.values()))