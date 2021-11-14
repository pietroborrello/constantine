#!/usr/bin/python3

import sys
import os
import glob
import pathlib
from collections import defaultdict

filepath = pathlib.Path(__file__).parent.absolute()

tainted_by_category = defaultdict(int)
total_by_category   = defaultdict(int)

for taint_file in glob.glob(str(filepath) + "/../examples/*/*.taint"):
    with open(taint_file, 'r') as f:
        lines = f.readlines()

    for line in lines[1:]:
        category = line.split(':')[0]
        flags = line.split(':')[1].replace('0', '').replace('B', 'b')

        tainted = (not flags.islower() or flags == '')

        if tainted:
            tainted_by_category[category] += 1
        total_by_category[category] += 1

for category in sorted(total_by_category.keys()):
    print(f'{category}: {tainted_by_category[category]}/{total_by_category[category]}')