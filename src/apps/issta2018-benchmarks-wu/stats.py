#!/usr/bin/env python3

import pandas as pd
from scipy.stats import gmean
from IPython import embed
import sys

data = pd.read_csv(sys.argv[1], sep=', ', engine='python')

def printStat(stat):
    if stat in data:
        print(stat.replace('_', ' ').capitalize()+':', gmean(data[stat].astype(float)))

# mean = data['cycles_overhead'].astype(float).mean(skipna=True)
printStat('cycles_overhead')
printStat('gemcycles_overhead (no AVX)')
printStat('size_overhead')
printStat('testing time (ms)')
printStat('linearization time (ms)')

# for stat in 'cycles4,cycles64,size4,size64'.split(','):
#     printStat(stat)