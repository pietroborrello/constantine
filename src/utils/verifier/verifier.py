#!/usr/bin/env python3
import sys
import r2pipe
import json
import networkx as nx

assert len(sys.argv) > 2
binary = sys.argv[1]
function = sys.argv[2]

r = r2pipe.open(binary)
r.cmd('aaa')
r.cmd(f's {function}')
json_graph = json.loads(r.cmd('agj'))[0]

blocks = json_graph['blocks']

forward_jumps = set()
jumps_graph = nx.DiGraph()

# collect all the jumps
for block in blocks:
    # # is the last op really a jmp?
    # if block['ops'][-1]['type'] not in {'jmp', 'cjmp'}:
    #     continue
    if 'jump' not in block:
        # return block
        continue

    block_addr = block['offset']
    jmp_target = block['jump']
    fallthrough = block['fail'] if 'fail' in block else None

    jumps_graph.add_edge(block_addr, jmp_target)

    jmp_offset = jmp_target - block_addr
    print(f"0x{block_addr:x} -> 0x{jmp_target:x}: offset {jmp_offset}")
    if fallthrough:
        # print(f"0x{block_addr:x} -> 0x{fallthrough:x}: offset {fallthrough - block_addr}")
        jumps_graph.add_edge(block_addr, fallthrough)

    # really a forward jump
    if jmp_offset > 0 and block['ops'][-1]['type'] in {'jmp', 'cjmp'}:
        forward_jumps.add((block_addr, jmp_target, fallthrough))

# (i.e. only loop exit condition)
for jmp_site, jmp_target, fallthrough in forward_jumps:
    if not fallthrough or jmp_site not in nx.descendants(jumps_graph, fallthrough) or jmp_site in nx.descendants(jumps_graph, jmp_target):
        print(f"ERROR: 0x{jmp_site:x} should not have forward jumps")
        exit(1)

exit(0)