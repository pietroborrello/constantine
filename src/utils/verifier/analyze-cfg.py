#!/usr/bin/env python3
import sys
import r2pipe
import json
import networkx as nx
import pydot
from networkx.drawing.nx_pydot import write_dot as puh
import os
#import IPython

assert len(sys.argv) > 2
binary = sys.argv[1]
starting_function = sys.argv[2]
r = r2pipe.open(binary)
r.cmd('aaa')

function_queue = set()
analysed_functions = set()

function_queue.add(starting_function)

def checkDominatorsInvariant(revcfg, start, domTree):
    global function # TODO
    print(f"===> Running dominance analysis on function {function}... <===")
    revcfg = nx.DiGraph()
    sinks = []
    for node in cfg.nodes:
        revcfg.add_node(node, label=hex(node))
        # find exit node(s) while at it
        if len(list(cfg.adj[node])) is 0:
            sinks.append(node)
    assert len(sinks) == 1
    tail = sinks[0]
    #revcfg.add_nodes_from(cfg.nodes)
    for (a, b) in cfg.edges:
        revcfg.add_edge(b, a)
    #puh(revcfg, "revcfg.dot")
    #os.system("dot -Tpng -o revcfg.png revcfg.dot")

    immPostDoms = nx.immediate_dominators(revcfg, tail)
    #print(immPostDoms)

    nodes = list(cfg.nodes)
    valid = True
    for node in nodes:
        successors = list(cfg.adj[node])
        if len(successors) > 2:
            print(f"Skipped node {node:x} with out-degree {len(successors)}")
        if len(successors) != 2:
            continue
        print(f"Processing {node:x}...")
        assert(node in immPostDoms)
        ipd = immPostDoms[node]
        if ipd == node:
            print(f"Self loop found at block {node:x}")
            continue
        # check number of predecessors for IPD
        ipds_preds = list(revcfg.adj[ipd])
        if len(ipds_preds)!= 2:
            print(f"IPD {ipd:x} has in-degree {len(ipds_preds):x}")
            continue
        # check if ipd is dominated by node
        if ipd not in nx.descendants(domTree, node):
            print(f"IPD {ipd:x} is not dominated by {node:x}")
            continue
        # final step: DFS as in cfl.cpp
        dfs = list(nx.dfs_edges(cfg, source=node, depth_limit=100)) # TODO limit..
        found = False
        succ = None
        for (a, b) in dfs:
            if b == ipd:
                break
            if len(list(cfg.adj[b])) is 2:
                # check if b dominates ipd
                if ipd in nx.descendants(domTree, b):
                    succ = b
                    found = True
                    break
        if found:
            print(f"Found successor {succ:x} that dominates IPD {ipd:x} of {node:x}")
        else:
            print(f"{function} -> ERROR: found a potential merge point for {node:x} with IPD {ipd:x}!")
            valid = False
    return valid

def checkReducibleGraph(cfg):
    global function
    # see https://www.cs.colostate.edu/~mstrout/CS553Fall06/slides/lecture13-control.pdf
    cfgcopy = nx.DiGraph()
    cfgcopy.add_nodes_from(cfg.nodes)
    cfgcopy.add_edges_from(cfg.edges)

    changed = True
    iterations = 0
    while changed:
        #puh(cfgcopy, f"red-{iterations}.dot")
        #os.system(f"dot -Tpng -o red-{iterations:02d}.png red-{iterations}.dot")
        changed = False
        #print("Iteration: "+str(iterations))
        iterations = iterations + 1
        nodes = list(cfgcopy.nodes)
        for node in nodes:
            successors = list(cfgcopy.adj[node]) # ==successors for DAG
            # attempt T1: remove self-loop (edge: node->node)
            if node in successors:
                #print(f"SELF LOOP for {node}")
                cfgcopy.remove_edge(node, node)
                changed = True
                break
            # attempt T2: if node has a unique predecessor, then remove node
            # and make all the successors be successors of its predecessor
            predecessors = []
            for (a, b) in cfgcopy.edges:
                if b == node:
                    predecessors.append(a)
            if len(predecessors) == 1:
                #print(f"DELETE for {node}")
                pred = predecessors[0]
                successors = list(cfgcopy.adj[node])
                cfgcopy.remove_edge(pred, node)
                for succ in successors:
                    cfgcopy.remove_edge(node, succ)
                    cfgcopy.add_edge(pred, succ)
                cfgcopy.remove_node(node)
                changed = True
                break
            else:
                pass
                #print("Number of predecessors: "+str(len(predecessors)))
    
    print(f"{function} -> Iterations required by reducibility test: {iterations}")
    if len(cfgcopy.nodes) != 1:
        print(f"{function} -> ERROR: Irreducible graph!")
        return False
    return True

def checkLoopAnalysis(cfg, start, domTree):
    global function
    print(f"===> Running loop analysis on function {function}... <===")
    isReducible = checkReducibleGraph(cfg)
    if not isReducible:
        return False

    ## Look for natural loops
    # Credits: http://pages.cs.wisc.edu/~fischer/cs701.f14/finding.loops.html
    descendants = {}
    for domTreeNode in domTree.nodes:
        descendants[domTreeNode] = nx.descendants(domTree, domTreeNode)

    # Once dominators are computed, we can define a back edge. An arc (or edge)
    # from node N to node H is a back edge if H dominates N. Node H is the
    # "header" of the loop (the place where the loop is entered). The back edge
    # is the "jump back" to the header that starts the next iteration.
    backedges = []
    for (a, b) in cfg.edges:
        if a in descendants[b] or a == b:
            print(f"Backedge found: {a:x} -> {b:x}")
            backedges.append((a, b))
    #print(backedges)

    # The body of the loop defined by a back edge from N to H includes N and H,
    # as well as all predecessors of N (direct and indirect) up to H. H's
    # predecessors are not included.
    loops = {}
    for (node, header) in backedges:
        loops[header] = {header}
        body = loops[header]
        s = [node]
        while len(s) != 0:
            d = s.pop()
            if d not in body:
                body.add(d)
                for pred in cfg.predecessors(d):
                    s.append(pred)

    # for loop in loops.keys():
    #     print(f"Loop body for {loop:x}")
    #     print(loops[loop])

    ## The desired check, at last :-P
    ## Assumption: we have no indirect branches, so either a jump is unconditional
    ## and to a fixed destination, or is conditional (direct, thus 2 destinations).
    ## 
    ## TODO verify if the following invariant is correct
    ## Given a node with out degree 2, we want either (i) one is part of some loop
    ## and the other doesn't or (ii) both are contained in loops, but one is part
    ## of some loop that doesn't contain the other.
    valid = True
    for node in cfg.nodes:
        successors = list(cfg.adj[node])
        if len(successors) > 1:
            assert(len(successors) == 2)
            a = successors[0]
            b = successors[1]
            #print(f"branch: 0x{a:x} -> 0x{b:x}")
            a_loops = set()
            b_loops = set()
            for loop in loops.keys():
                if a in loops[loop]:
                    a_loops.add(loop)
                if b in loops[loop]:
                    b_loops.add(loop)
            if len(a_loops.union(b_loops)) != len(a_loops.intersection(b_loops)):
                print(f"Branch at 0x{node:x} is OK")
            else:
                print(f"{function} -> Branch at 0x{node:x} is KO!!!")
                valid = False
    return valid


while len(function_queue):
    function = function_queue.pop()
    analysed_functions.add(function)
    r.cmd(f's {function}')
    # collect all the called functions
    called_funcs = json.loads(r.cmd('agcj'))
    if len(called_funcs):
        for func in called_funcs[0]['imports']:
            if func not in analysed_functions:
                function_queue.add(func)
    # analyze the function
    json_graph = json.loads(r.cmd('agj'))[0]
    blocks = json_graph['blocks']
    start = json_graph['offset']
    #IPython.embed()
    forward_jumps = set()
    cfg = nx.DiGraph()

    # collect all the jumps
    for block in blocks:
        block_addr = block['offset']
        cfg.add_node(block_addr, label=hex(block_addr))
        if 'jump' not in block:
            continue
        jmp_target = block['jump']
        fallthrough = block['fail'] if 'fail' in block else None
        cfg.add_edge(block_addr, jmp_target)
        if fallthrough:
            cfg.add_edge(block_addr, fallthrough)

    puh(cfg, "cfg.dot")
    os.system("dot -Tpng -o cfg.png cfg.dot")

    # compute dominator information (used by both analyses)
    immDoms = nx.immediate_dominators(cfg, start)
    #print(immDoms)
    domTree = nx.DiGraph()
    for a in immDoms.keys():
        b = immDoms[a]
        if a == b:
            continue
        domTree.add_edge(b, a)
    #puh(domTree, "domTree.dot")
    #os.system("dot -Tpng -o domTree.png domTree.dot")

    # Addition: check invariant that we enforce at IR level
    checkInvariant = checkDominatorsInvariant(cfg, start, domTree)
    checkLoops = checkLoopAnalysis(cfg, start, domTree)
    print(f"===> Results for function {function}... <===")
    if not (checkInvariant and checkLoops):
        if checkInvariant != checkLoops:
            print(f"{function} -> ERROR: Invalid branches found by either analyses (WARNING: divergence)")
        else:
             print(f"{function} -> ERROR: Invalid branches found by both analyses!")
        exit(1)
    else:
        print("PASS")