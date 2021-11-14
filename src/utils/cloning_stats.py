#!/usr/bin/python3

import sys
from collections import defaultdict
from pprint import pprint
from tabulate import tabulate

if len(sys.argv) < 2: 
    print("usage: %s <filename>", sys.argv[0])
    exit(1)

with open(sys.argv[1]) as f:
    functions = f.readlines()

unique_functions = defaultdict(int)
tainted_functions = defaultdict(int)

for func in functions:
    tainted = False
    extracted = False
    if '__cfl_' in func:
        tainted = True
        func = func.replace('__cfl_', '')

    if 'branch_' in func:
        extracted = True
        func = func.replace('branch_', '')
    if 'loop_' in func:
        extracted = True
        func = func.replace('loop_', '')

    if func.count('.') > 2:
        assert extracted
        func = '.'.join(func.split('.')[:2])
    
    orig_func = func.split('.')[0]

    if not extracted:
        unique_functions[orig_func] += 1
        if tainted: tainted_functions[orig_func] += 1

tab = []
total = 0
total_taint = 0
for f in unique_functions:
    tab.append([f, unique_functions[f], tainted_functions[f]])
    total += unique_functions[f]
    total_taint += tainted_functions[f]
tab.append(['TOTAL', total, total_taint])

print(tabulate(tab, headers=['Function', 'Clones', 'Tainted Clones'], tablefmt='orgtbl'))