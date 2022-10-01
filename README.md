# Constantine
This is the home of `Constantine`: a compiler-based system to automatically harden programs against microarchitectural side channels.

`Constantine` pursues a radical design point where secret dependent control and data flows are completely linearized: all the possible secret-dependent code/data memory accesses are always executed regardless of the particular secret value encountered.
Thanks to carefully designed optimizations such as *just-in-time loop linearization* and *aggressive function cloning*, `Constantine` provides a scalable solution, while supporting all the common programming constructs in real-world software. 

This is the high-level architecture of `Constantine`:

<br/><br/>
<img src="https://user-images.githubusercontent.com/18199462/115702424-37eb6780-a369-11eb-88a5-83e6eb28e05f.png">
<br/><br/>

`Constantine` outperforms prior comprehensive solutions in terms of both performance and compatibility, while also providing stronger security guarantees. For example, we show `Constantine` yields overheads as low as 16% for cache-line attacks on standard benchmarks. Moreover, `Constantine` can protect ECDSA signatures in the [wolfSSL](https://www.wolfssl.com/) embedded library to complete a constant-time modular multiplication in 8 ms.

The design behind `Constantine` is described in the paper *Constantine: Automatic Side-Channel Resistance Using Efficient Control and Data Flow Linearization* (preprint available [here](http://www.diag.uniroma1.it/~delia/papers/ccs21.pdf) or on [arXiv](https://arxiv.org/abs/2104.10749)) which appeared in the [ACM CCS 2021](https://www.sigsac.org/ccs/CCS2021/) conference. 

## How does Constantine work?

Constantine transforms programs into their constant time equivalent. It can handle *secret dependent branches*, *secret depentent loops* and *secret dependent memory accesses*, i.e., basically everything.

### Secret dependent branches

Constantine rewires secret dependent branches so that both sides are always executed, while propagating only the side-effects of the side that should have been executed.

![image](https://user-images.githubusercontent.com/18199462/193406537-81d02666-08ba-4079-8437-2fce38ce89ac.png)

For example, given an if-else branch, Constantine will make the program always execute both sides, wrap any load and stores to constant time wrappers (`ct_load/ct_store`, more on this later), and propagate side-effects with constant time selection primitives (`ct_select`).

![image](https://user-images.githubusercontent.com/18199462/193406519-b747d931-ca21-46c3-8956-ba41645afbe6.png)

This results in constant time execution of forward control flow that depends on secrets.

### Secret dependent loops

Constantine performs Just-in-Time Loop linearization: it hijacks the loop trip count to dynamically insert padding loop iterations. This avoids leaking secret data through the loop conditions (i.e., how many times a loop is executed).

![image](https://user-images.githubusercontent.com/18199462/193406696-5d7281f8-4776-45c4-afd1-d1b9752aa656.png)

Thus, the number of times a loop gets executed will remain the same for the whole program execution, while avoiding forwarding computation to the visible state during the iterations the loop should not have been executed.

### Secret dependent memory accesses

For each sensitive memory access, Constantine makes the resulting program access all the locations that the original program can possibly reference for any initial input. All while only updating/returning the values the original program was supposed to touch.

![image](https://user-images.githubusercontent.com/18199462/193406979-0046ace8-abf5-4e06-91f3-8db2609e063f.png)

We leverage pointer analysis to map each memory access to the set of objects it may touch, and then leverage fast striding over each object to touch all the possible entries that may be accessed.

![image](https://user-images.githubusercontent.com/18199462/193407055-582db691-b18a-4ca2-97d7-06a0b7cbfc91.png)

While any possible offset is accessed, Constantine makes sure only the location that the program was supposed to access is returned or updated, using constant time primitives.
This allows us to protect any memory access that may depend on secret values, as any active/passive attacker will always observe the same access pattern across any execution.

### How can all of this scale?!

We spent an *insane* amount of time optimizing this radical design: 

* We leverage dynamic taint analysis to restrict our protection to the only branches/loops/memory accesses in the code that are secret dependent.
* We leverage precise pointer analysis to identify the exact fields of each object that may be touched in each memory access.
* We leverage AVX2/AVX512 to perform fast striding over objects.
* We track the object lifetimes so that the program will stride over only active objects/
* We leverage function cloning to add context sensitivity to the analyses.
* We designed all the techniques to be transparent to the compiler, thus it can safely optimize the resulting program.
* We leverage indirect call promotion and switch lowering to avoid the need of protecting indirect branches.
* We promote stack variables to globals on non-recursive functions to avoid tracking the lifetime of such stack variables.


## Getting Started

Constantine is based on LLVM 9. Compile and install all the LLVM passes:

```bash
./install.sh
. ./setup.sh
./llvm_compile_dfsan_cpp.sh
(cd passes && make install)
(cd lib && make install)
(cd utils/pintool && make check-profiler)
```

## Benchmarks
To run the benchmarks:
```bash
cd ./apps/$BENCH
./run_all
```
This will produce a result.csv file with all the measurements.

## Using Constantine

We provide a compiler wrapper to linearize arbitrary source file.

It will automatically:
1. produce a bitcode file.
2. build it with a dfsan profiler for dynamic taint analysis.
3. run a random-input test suite over the profiler that executes the various paths of the program to gather taint and loops information.
4. automatically protect all the branches, loops and memory accesses that the profiling phase identified as secret dependent.
5. produce a hardened binary.

**NOTICE1**: Constantine protects only the branches, memory accesses and loops that observes being secret sensitive during the random-input profiling phase. A simple random testing is usually enough for cryptographic algorithms, but beware that if a branch/memory-access is not explored it will not be protected, even if potentially secret sensitive. Provide an actual test suite to constantine in case random testing is not effective in exploring program states. 

**NOTICE2**: All inputs are considered secret sensitive by default. Constantine observes input flowing trough explicit `read`, `pread` and `fread`. Add hooks in `./src/lib/dft/hook.c` in case this is not enough.


Use `./constantine` for C sources and `./constantine++` for C++.

### example output:
```
$ ./constantine -O1 apps/issta2018-benchmarks-wu/examples/chronos/aes.c -o aes.out
[+] building taint profiler
    [ ... statistics ...]
[+] running taint profiler
[+] processing taint information
[+] building loop profiler
    [ ... more statistics ...]
[+] running loop profiler
[+] building constant time version
    [ ... more and more statistics ...]
```

## passes

The folder contains all the custom passes needed by Constantine. A brief non-complete list here:
- CGC: clone all the functions in the module to make them unique
- branch-extract: extract all the selected branched in new functions, to deal with them separatedly
- CFL: linearize control flow, assumes structurized CFG, and that each function has a single, normalized, branch
- coverage-id: assign unique ID to each instruction in the module to identify them between passes
- DFL: linearize data flow
- fix-[...]: different passes to fix bugs of llvm CFG structurization pass
- hook: insert dfsan wrappers and div hooks
- ICP: indirect call promotion
- loops-CFL: linearize loops, assumes structurized CFG and that each function as a single normal loop
- mark-induction-variables: find and mark loop induction variables for DFL optimizations
- remove-[...]: different passes to transform CFG to remove unwanted graph structures
- set-norecurse-ext: set and forward norecurse attribute along the callgraph dealing with external calls
- stack-vars-promotion: promote all the stack variables in non-recursive functions to globals, to optimize DFL usage
- taintglb: taint global variables based on regexes


## lib

The folder contains all the libraries that our passes rely on:
- cfl: all the CFL helpers needed by the CFL pass. The pass assumes this has been linked with the code it analyzes
- dfl: all the DFL helpers needed by the DFL pass. The pass assumes this has been linked with the code it analyzes
- cgc: CGC helpers used when indirect calls are not promoted with ICP
- dft: dfsan wrappers to taint inputs and log taints. Supported input functions are: read, fread, pread
- utils: various wrappers to deal with memset/memcpy functions

## vscode-extension

We provide in addition a vscode extension to visualize tainted instructions in the source code
Install it running `code --install-extension ./tainthighlight-0.0.1.vsix`.

It will parse the taint files generated by constantine. To activate it in vscode press `CTRL + shift + P` and execute `Highlight Tainted`.
To manually force the parsing of a taint file execute `Parse Taint File `.

![](./src/vscode-extension/tainthighlight/example.png)


## Cite
```
@inproceedings{constantine,
    author = {Borrello, Pietro and D'Elia, Daniele Cono and Querzoni, Leonardo and Giuffrida, Cristiano},
    title = {Constantine: Automatic Side-Channel Resistance Using Efficient Control and Data Flow Linearization},
    year = {2021},
    publisher = {Association for Computing Machinery},
    booktitle = {Proceedings of the 2021 ACM SIGSAC Conference on Computer and Communications Security},
    location = {Seoul, South Korea},
    series = {CCS '21},
    doi={10.1145/3460120.3484583},
}
```
