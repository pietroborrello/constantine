#!/usr/bin/env python3

import sys
from colors import *
from PIL import Image
import io
from tqdm import tqdm

COLORED = False
GREEN  = b'\x00\x80\x00'#(0, 128, 0)
YELLOW = b'\xff\xff\x00'#(255, 255, 0)
RED    = b'\xff\x00\x00'
BLUE   = b'\x00\x00\xff'
DARK_BLUE=B'\x2E\x40\x53'
WHITE  = b'\xff\xff\xff'#(255, 255, 255)

# darken color `c` for `times` times
def darker(c, times):
    assert len(c) == 3
    res = bytearray(len(c))
    for ii,cc in enumerate(c):
        new_val = cc-(times*5)
        res[ii] = new_val if new_val > 0 else cc
    return bytes(res)

def get_color(line, darkness):
    if 'taken: 0' in line:
        return darker(YELLOW, darkness)
    elif 'taken: 1' in line:
        return darker(GREEN, darkness)
    elif('Loop preheader' in line or 'Loop exit' in line):
        return darker(RED, darkness)
    elif "LOAD" in line or "STORE" in line:
        if "SINGLE" in line:
            return darker(BLUE, darkness)
        else:
            return darker(DARK_BLUE, darkness)
    else:
        return darker(WHITE, darkness)


img_data = []
#from IPython import embed
#embed()

if len(sys.argv) < 2:
    print("usage: %s <trace>" % sys.argv[0])
    exit(1)

tracefile =     sys.argv[1]
tracefile_out = "{}.indent".format(tracefile)
tracefile_col = "{}.color".format(tracefile)
img_out       = "{}.png".format(tracefile)
IMG_WIDTH     = 1024

with open(tracefile) as f:
    lines = f.readlines()

indent = 0
max_indent = 0

with open(tracefile_out, 'w') as f, open(tracefile_col, 'w') as f_col:
    for line in tqdm(lines):
        line = line.strip()
        max_indent = max(max_indent, indent)
        assert(indent >= 0)
        img_data.append(get_color(line, indent))
        print (' ' * indent + line, file=f)

        if 'taken: 0' in line:
            print (' ' * indent + color(line, bg='yellow'), file=f_col)
        elif 'taken: 1' in line:
            print (' ' * indent +  color(line, bg='green'), file=f_col)
        else:
            print (' ' * indent + line, file=f_col)
        if "Loop preheader - " in line or 'Branching - ' in line: # either 'Loop preheader - ' or 'Branching - '
            indent += 1
        elif "Loop exit - " in line or 'Merging - ' in line:    # either 'Loop exit - ' or 'Merging - '
            indent -= 1

# lazily overfill
for _ in range(IMG_WIDTH):
    img_data.append(WHITE)

print("loading image...")
img = Image.frombytes('RGB', (IMG_WIDTH, len(lines)//IMG_WIDTH + 1), b''.join(img_data), 'raw')
print("saving image...")
img.save(img_out, "PNG", optimize=False, compress_level=0, quality=100)
print('saved image: {}'.format(img_out))
print('max_indent: {}\n'.format(max_indent))