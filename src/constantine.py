#!/usr/bin/env python3

from subprocess import run, check_call, check_output, DEVNULL, PIPE
import random
import shutil
import json
import sys
import os

import errno
from hashlib import sha256
from tempfile import gettempdir
from time import time, sleep
import click

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

SOURCE_EXTENSIONS = ('.c', '.cc', '.cpp', '.h',
                     '.hpp')
FILTER_EXTENSIONS = ('.c', '.cc', '.cpp', '.h',
                     '.hpp', '.o', '.obj', '.a', '.la')

# we take optimizations from O1, but we exclude -loop-unroll, -jump-threading, -pgo-memop-opt and -loop-unswitch as they usually create more complex CFGs
SAFE_OPTS='-tti -tbaa -scoped-noalias -assumption-cache-tracker -targetlibinfo -verify -ee-instrument -simplifycfg -domtree -sroa -early-cse -lower-expect -tti -tbaa -scoped-noalias -assumption-cache-tracker -profile-summary-info -forceattrs -inferattrs -ipsccp -called-value-propagation -attributor -globalopt -domtree -mem2reg -deadargelim -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -simplifycfg -basiccg -globals-aa -prune-eh -inline -functionattrs -domtree -sroa -basicaa -aa -memoryssa -early-cse-memssa -speculative-execution -basicaa -aa -lazy-value-info -correlated-propagation -simplifycfg -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -libcalls-shrinkwrap -loops -branch-prob -block-freq -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -tailcallelim -simplifycfg -reassociate -domtree -loops -loop-simplify -lcssa-verification -lcssa -basicaa -aa -scalar-evolution -loop-rotate -licm -simplifycfg -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -loop-simplify -lcssa-verification -lcssa -scalar-evolution -indvars -custom-loop-idiom -disable-custom-loop-idiom-memcpy -loop-deletion -mldst-motion -phi-values -basicaa -aa -memdep -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -gvn -phi-values -basicaa -aa -phi-values -memdep -memcpyopt -sccp -demanded-bits -bdce -basicaa -aa -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -lazy-value-info -correlated-propagation -basicaa -aa -phi-values -memdep -dse -loops -loop-simplify -lcssa-verification -lcssa -basicaa -aa -scalar-evolution -licm -postdomtree -adce -simplifycfg -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -barrier -elim-avail-extern -basiccg -rpo-functionattrs -globalopt -globaldce -basiccg -globals-aa -float2int -domtree -loops -loop-simplify -lcssa-verification -lcssa -basicaa -aa -scalar-evolution -loop-rotate -loop-accesses -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -loop-distribute -branch-prob -block-freq -scalar-evolution -basicaa -aa -loop-accesses -demanded-bits -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -loop-simplify -scalar-evolution -aa -loop-accesses -lazy-branch-prob -lazy-block-freq -loop-load-elim -basicaa -aa -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -simplifycfg -domtree -basicaa -aa -demanded-bits -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -slp-vectorizer -opt-remark-emitter -instcombine -loop-simplify -lcssa-verification -lcssa -scalar-evolution -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -loop-simplify -lcssa-verification -lcssa -scalar-evolution -licm -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -transform-warning -alignment-from-assumptions -strip-dead-prototypes -globaldce -constmerge -domtree -loops -branch-prob -block-freq -loop-simplify -lcssa-verification -lcssa -basicaa -aa -scalar-evolution -block-freq -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instsimplify -div-rem-pairs -simplifycfg -targetlibinfo -domtree -loops -branch-prob -block-freq'

script_dir = os.path.dirname(os.path.realpath(os.path.abspath(__file__)))

is_cxx = "++" in sys.argv[0]
if is_cxx:
    cc = 'clang++'
else:
    cc = 'clang'

if 'LLVM_SRC' not in os.environ:
    print('[-] LLVM_SRC not set')
    exit(1)
LLVM_SRC = os.environ['LLVM_SRC']

is_debug = os.getenv("CONSTANTINE_DEBUG") is not None
compiler_path = os.getenv("LLVM_COMPILER_PATH")

def gclang_exec(args):
    if isinstance(args, str):
        args = args.split()
    if os.getenv("GCLANG_PATH"):
        cc_name = os.environ["GCLANG_PATH"]
    else:
        cc_name = "gclang"
    if is_cxx:
        if os.getenv("GCLANGXX_PATH"):
            cc_name = os.environ["GCLANGXX_PATH"]
        else:
            cc_name = "gclang++"
    argv = [cc_name] + args
    if is_debug:
        print(" ".join(argv), file=sys.stderr)
    return check_call(argv)


def cc_exec(args):
    if isinstance(args, str):
        args = args.split()
    if os.getenv("REAL_CC_PATH"):
        cc_name = os.environ["REAL_CC_PATH"]
    elif compiler_path is not None:
        cc_name = os.path.join(compiler_path, "clang")
    else:
        cc_name = "clang"
    if is_cxx:
        if os.getenv("REAL_CXX_PATH"):
            cc_name = os.environ["REAL_CXX_PATH"]
        elif compiler_path is not None:
            cc_name = os.path.join(compiler_path, "clang++")
        else:
            cc_name = "clang++"
    argv = [cc_name] + args
    if is_debug:
        print(" ".join(argv), file=sys.stderr)
    return check_call(argv)

def opt_add_passes_loads(args):
    res = []
    dir_path = os.path.dirname(os.path.realpath(__file__))
    arg: str
    for arg in args:
        if arg.startswith('-'):
            pass_name = arg[1:]
            if os.path.exists(f'{dir_path}/bin/{pass_name}.so'):
                res.append(f'-load={dir_path}/bin/{pass_name}.so')
        res.append(arg)
    return res


def opt_exec(args, wrapper_cmd=None):
    if isinstance(args, str):
        args = args.split()
    args = opt_add_passes_loads(args)
    if os.getenv("OPT_PATH"):
        cc_name = os.environ["OPT_PATH"]
    elif compiler_path is not None:
        cc_name = os.path.join(compiler_path, "opt")
    else:
        cc_name = "opt"
    argv = [cc_name] + args
    if wrapper_cmd is not None:
        argv = wrapper_cmd + argv
    if is_debug:
        print(" ".join(argv), file=sys.stderr)
    ret = check_call(argv)
    return ret

def extract_exec(args):
    if isinstance(args, str):
        args = args.split()
    if os.getenv("EXTRACT_PATH"):
        ext_name = os.environ["EXTRACT_PATH"]
    elif compiler_path is not None:
        ext_name = os.path.join(compiler_path, "llvm-extract")
    else:
        ext_name = "llvm-extract"
    argv = [ext_name] + args
    if is_debug:
        print(" ".join(argv), file=sys.stderr)
    ret = check_call(argv)
    return ret

def link_exec(args):
    if isinstance(args, str):
        args = args.split()
    if os.getenv("LINK_PATH"):
        tool_name = os.environ["LINK_PATH"]
    elif compiler_path is not None:
        tool_name = os.path.join(compiler_path, "llvm-link")
    else:
        tool_name = "llvm-link"
    argv = [tool_name] + args
    if is_debug:
        print(" ".join(argv), file=sys.stderr)
    ret = check_call(argv)
    return ret

def strip_exec(args):
    if isinstance(args, str):
        args = args.split()
    if os.getenv("STRIP_PATH"):
        tool_name = os.environ["STRIP_PATH"]
    elif compiler_path is not None:
        tool_name = os.path.join(compiler_path, "llvm-strip")
    else:
        tool_name = "llvm-strip"
    argv = [tool_name] + args
    check_call(argv, stdout=DEVNULL, stderr=DEVNULL)

def get_bc(filename, bc_filename=None, strict_mode=False):
    if bc_filename is None:
        bc_filename = filename + '.bc'
    if os.getenv("GETBC_PATH"):
        cc_name = os.environ["GETBC_PATH"]
    else:
        cc_name = "get-bc"
    argv = [cc_name, '-b', '-o', bc_filename]
    if strict_mode:
        argv.append('-S')
    argv.append(filename)
    if is_debug:
        print(" ".join(argv), file=sys.stderr)
    return check_call(argv)


# gclang fails extracting the bitcode for source files that are inside a linker group
# so extract them, plus extract also `-o output` if it is in the linker group
def fix_linker_groups(args):
    last_group = 0
    # search all occurrences, a ValueError will end the search
    while True:
        try:
            #search for linker groups
            last_group = args.index('-Wl,--start-group', last_group)
            end_group = args.index('-Wl,--end-group', last_group)
            idx = last_group + 1
            while idx < end_group:
                arg = args[idx]
                if arg.endswith(SOURCE_EXTENSIONS):
                    args.insert(last_group, args.pop(idx))
                    last_group += 1
                elif arg == '-o':
                    # pop both the `-o` and the param
                    args.insert(last_group, args.pop(idx))
                    args.insert(last_group+1, args.pop(idx+1))
                    last_group += 2
                else:
                    idx += 1
            last_group = end_group + 1

        except ValueError:
            return

# build the dft-sanitized program to trace taint value
def build_dft(input, optimization_level):
    name = input[: input.rfind('.')]

    if is_cxx:
        cflags = f"-O1 -stdlib=libc++ -I{LLVM_SRC}/build-dfsan/include/c++/v1" + os.environ.get('CXXFLAGS', '')
        ldflags = f"-stdlib=libc++ -L{LLVM_SRC}/build-dfsan/lib64 -Wl,--start-group,-lc++abi" + os.environ.get('LDFLAGS', '')
    else:
        cflags = os.environ.get('CFLAGS', '')
        ldflags = os.environ.get('LDFLAGS', '')

    CFLAGS  = f"-O{optimization_level} -fno-unroll-loops -mllvm -x86-cmov-converter=0 -g"
    OFLAGS  = f"-O{optimization_level}"
    LDFLAGS = f"-O{optimization_level} " + ldflags

    DFSAN_ABILIST = check_output(f"{cc} {cflags} -fsanitize=dataflow -c {input} -### 2>&1 | grep sanitize | sed 's/.*-fsanitize-blacklist=\([^\\\"]*\).*/\\1/g'", shell=True).decode().strip()
    # save dfsan abilist
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open('dfsan_abilist.txt', 'wb') as f:
        check_call(f'cat {DFSAN_ABILIST} {dir_path}/lib/dft/dfsan.abilist', shell=True, stdout=f)

    # obtain the bitcode from the input
    cc_exec(f'-Xclang -disable-O0-optnone -g {cflags} -flto -c -o {name}.base.bc {input} -fno-exceptions')
    link_exec(f'-o {name}.linked.bc {name}.base.bc')

    # SSA form and remove unnneeded functions
    opt_exec(f'-mem2reg -internalize -internalize-public-api-list=main -globaldce {SAFE_OPTS} -internalize -internalize-public-api-list=main -globaldce -check-undefined -o {name}.opt.bc {name}.linked.bc')

    # promote indirect calls to if-else constructs
    opt_exec(f'-icp -icp-type -icp-abort -stat=0 -nander -check-undefined -o {name}.icp.bc {name}.opt.bc')

    # simplify the CFG and normalize it
    opt_exec(f'-scalarizer -scalarize-load-store -fix-scalarizer -lowerswitch -lowerinvoke -loop-simplify -mem2reg -remove-unreachable -remove-unreachable-funcs=.* -remove-selfloops -remove-selfloops-funcs=.* -remove-dup-lifetimes -mergereturn -fix-irreducible -unify-loop-exits -insert-compares -custom-structurizecfg -branch-enhance -internalize -internalize-public-api-list=main -globaldce -check-undefined -o {name}.cfgnorm.bc {name}.icp.bc')

    # aggressive cloning
    opt_exec(f'-set-norecurse-ext -functionattrs -rpo-functionattrs -cgc -cgc-funcs=.* -cgc-clone-prefix= -cgc-icalls=0 -cgc-unique -internalize -internalize-public-api-list=main -globaldce -check-undefined -o {name}.cgc0.bc {name}.cfgnorm.bc')

    # assign ID to every instruciton to identify them
    opt_exec(f'-coverage-id -coverage-id-b-gids -coverage-id-i-bids -check-undefined -o {name}.coverage-id.bc {name}.cgc0.bc')

    # link the needed libraries
    link_exec(f' -o {name}.dft.bc {name}.coverage-id.bc {dir_path}/bin/dft.bcc')

    # hook the instructions we want to trace
    opt_exec(f'-check-undefined -o {name}.taintglb.bc {name}.dft.bc')
    opt_exec(f'-scalarizer -scalarize-load-store -lowerinvoke -hook -hook-inline -hook-base-args-tls=0 -hook-base-args=b-gid,i-bid -check-undefined -o {name}.hook.bc {name}.taintglb.bc')

    # insert the dfsan sanitizer code
    opt_exec(f'-dfsan -dfsan-abilist=dfsan_abilist.txt -fix-callsite-attrs {OFLAGS} -check-undefined -o {name}.final.bc {name}.hook.bc')

    # produce output
    cc_exec(f'{CFLAGS} -fPIC -DPIC -o {name}.final.o -c {name}.final.bc')
    cc_exec(f'{LDFLAGS} -fno-exceptions -fsanitize=dataflow -o {name}.dft.out -ldl {name}.final.o {dir_path}/lib/dft/dft.o')

# simple implementation where we do random testing, as it is enough for crypto algorithms
def get_next_input():
    return bytearray(random.getrandbits(8) for _ in range(128))
def get_test_suite_size():
    return 256

# run the test suite on the DFT program to gather taint information on the visited paths
def run_test_suite_dft(input, dft_log):
    dft_tmp = 'dft.raw'
    name = input[: input.rfind('.')]
    if os.path.exists(dft_tmp):
        os.remove(dft_tmp)

    # run the profiler for each input in the test suite
    for _ in range(get_test_suite_size()):
        input_bytes = get_next_input()
        check_output(f'{name}.dft.out', shell=True, input=input_bytes)
        # the binary will dump a dft.log file, save it
        with open(dft_log,  'rb') as r:
            with open(dft_tmp, 'ab') as w:
                w.write(r.read())
    
    with open(dft_log, 'wb') as f:
        check_call(f'cat {dft_tmp} | sort | uniq', shell=True, stdout=f)
    os.remove(dft_tmp)

def process_taint_info(input, taint_file, taint_log, dft_log_file):
    name = input[: input.rfind('.')]
    with open(taint_file, 'wb') as f:
        f.write(b'*** Tainted instructions:')
    dft_tmp = 'dft.tmp'
    with open(dft_tmp, 'wb') as f:
        check_call(f'sed "s/.*0x/0x/g" {dft_log_file}', stdout=f, shell=True)
    check_call(f'llvm-symbolizer -s --inlining=0 --functions=none --obj={name}".dft.out" < {dft_tmp} | grep -v "^$" | sed "s/??.*//g" > {dft_tmp}.symb', shell=True)
    check_call(f'paste {dft_log_file} {dft_tmp}.symb >> {taint_file}', shell=True)

    # process taints
    check_call(f'cut -f2,3,4 -d":" --output-delimiter=" " -s {dft_log_file} > {taint_log}', shell=True)

def build_loop_trace(input, taint_log, optimization_level):
    name = input[: input.rfind('.')]
    dir_path = os.path.dirname(os.path.realpath(__file__))
    
    CFLAGS  = f"-O{optimization_level} -fno-unroll-loops -mllvm -x86-cmov-converter=0 -g"
    OFLAGS  = f"-O{optimization_level}"
    LDFLAGS = f"-O{optimization_level} "

    # load metadata on tainted instructions
    opt_exec(f'-loadtainted -tainted-file={taint_log} -check-undefined -o {name}.tainted.bc {name}.coverage-id.bc')

    # simplify unneded functions from the CFG, and perform some further optimization
    opt_exec(f'-internalize -internalize-public-api-list=main -globaldce -remove-dup-lifetimes -set-norecurse-ext -functionattrs -rpo-functionattrs -forward-geps -branch-extract -branch-extract-funcs=.* -check-undefined -o {name}.extracted.bc {name}.tainted.bc')

    # aggressive function cloning
    opt_exec(f'-cgc -cgc-funcs=__cfl_.* -cgc-clone-prefix=__cfl_ -cgc-icalls=0 -cgc-unique -internalize -internalize-public-api-list=main -globaldce -check-undefined -o {name}.cgc.bc {name}.extracted.bc')

    # link all the needed libraries
    link_exec(f'-o {name}.linked_2.bc {name}.cgc.bc {dir_path}/bin/cfl.bcc {dir_path}/bin/dfl.bcc')

    # insert loop profiling code
    opt_exec(f'-loops -loop-simplify -lcssa -loops-cfl -loops-cfl-funcs=__cfl_.* -loops-cfl-dump-conf -check-undefined -o {name}.loops-cfl.bc {name}.linked_2.bc')
    opt_exec(f'-internalize -internalize-public-api-list=main -fix-callsite-attrs {OFLAGS} -check-undefined -o {name}.final.bc {name}.loops-cfl.bc')

    # produce output
    cc_exec(f'{CFLAGS} -fPIC -DPIC -o {name}.final.o -c {name}.final.bc')
    cc_exec(f'{LDFLAGS} -fno-exceptions -o {name}.dumper.out {name}.final.o')

# run the test suite on the loop instrumented program to gather taint information on the visited paths
def run_test_suite_loop(input, loop_log):
    log_tmp = 'loops-cfl.raw'
    name = input[: input.rfind('.')]
    if os.path.exists(log_tmp):
        os.remove(log_tmp)
    
    # run the profiler for each input in the test suite
    for _ in range(get_test_suite_size()):
        input_bytes = get_next_input()
        check_output(f'{name}.dumper.out 2>{loop_log}', shell=True, input=input_bytes)
        # the binary will dump loop info, save it
        with open(loop_log,  'rb') as r:
            with open(log_tmp, 'ab') as w:
                w.write(r.read())
    
    with open(loop_log, 'wb') as f:
        check_call(f'cat {log_tmp} | sort | uniq', shell=True, stdout=f)
    os.remove(log_tmp)

def build_constant_time(input, output, taint_log, loop_log, optimization_level):
    name = input[: input.rfind('.')]
    dir_path = os.path.dirname(os.path.realpath(__file__))
    
    CFLAGS  = f"-O{optimization_level} -fno-unroll-loops -mllvm -x86-cmov-converter=0 -g -fno-delete-null-pointer-checks "
    OFLAGS  = f"-O{optimization_level}"
    LDFLAGS = f"-O{optimization_level} "

    # load metadata on tainted instructions
    opt_exec(f'-loadtainted -tainted-file={taint_log} -o {name}.tainted.bc {name}.coverage-id.bc')

    # simplify unneded functions from the CFG, and perform some further optimization
    opt_exec(f'-internalize -internalize-public-api-list=main -globaldce -remove-dup-lifetimes -set-norecurse-ext -functionattrs -rpo-functionattrs -forward-geps -mark-induction-variables -mark-only-simple-vars=0 -convert-ptr-to-indexes -taint-stats -branch-extract -branch-extract-funcs=.* -o {name}.extracted.bc {name}.tainted.bc')

    # aggressive function cloning
    opt_exec(f'-cgc -cgc-funcs=__cfl_.* -cgc-clone-prefix=__cfl_ -cgc-icalls=0 -cgc-unique -internalize -internalize-public-api-list=main -globaldce -o {name}.cgc.bc {name}.extracted.bc')

    # stack variables promotion
    opt_exec(f'-functionattrs -rpo-functionattrs -stack-vars-promotion -stack-vars-promotion-funcs=.* -stack-vars-promotion-cfl-funcs=__cfl_.* -stat=0 -modelConsts -allow-fi-prom=0 -fieldlimit=4294967295 -o {name}.promoted.bc {name}.cgc.bc')

    # link all the needed libraries
    link_exec(f'-o {name}.linked_2.bc {name}.promoted.bc {dir_path}/bin/cfl.bcc {dir_path}/bin/dfl.bcc')

    # linearize Data Flow
    opt_exec(f'-dfl -dfl-funcs=.* -dfl-cfl-funcs=__cfl_.* -dfl-avx2=1 -stat=0 -modelConsts -allow-fi-prom=0 -fieldlimit=4294967295 -o {name}.dfl.bc {name}.linked_2.bc')

    # linearize Control Flow
    opt_exec(f'-cfl -cfl-funcs=__cfl_.* -cfl-protect-mem=0 -cfl-protect-branches=1 -o {name}.cfl.bc {name}.dfl.bc')

    # linearize Loops
    opt_exec(f'-loops -loop-simplify -lcssa -loops-cfl -loops-cfl-funcs=__cfl_.* -loops-cfl-protect-stores=1 -loops-cfl-conf={loop_log} -o {name}.loops-cfl.bc {name}.cfl.bc')

    # linearize Divisions/Mod
    opt_exec(f'-hook -hook-funcs=__cfl_.* -o {name}.div.bc {name}.loops-cfl.bc')
    opt_exec(f'-internalize -internalize-public-api-list=main -fix-callsite-attrs {OFLAGS} -o {name}.final.bc {name}.div.bc')

    # produce output
    cc_exec(f'{CFLAGS} -fPIC -DPIC -o {name}.final.o -c {name}.final.bc')
    cc_exec(f'{LDFLAGS} -fno-exceptions -o {output} {name}.final.o')



@click.command()
@click.argument('input', type=click.Path(exists=True))
@click.option('-o', '--output', type=str, default='')
@click.option('-O', '--optimization_level', type=int, default=3)
def constantine_compile(input:str, output, optimization_level:int):

    name = input[: input.rfind('.')]
    taint_file = f'{name}.taint'
    if output == '':
        output = f'{name}.out'

    # build the dft version of the program to gather taint info
    print(f'[{bcolors.OKGREEN}+{bcolors.ENDC}] building taint profiler')
    build_dft(input, optimization_level)

    # run the test suite to gather taint info
    dft_log_file = 'dft.log'
    print(f'[{bcolors.OKGREEN}+{bcolors.ENDC}] running taint profiler')
    run_test_suite_dft(input, dft_log_file)

    # process the taint information and symbolize it
    taint_log = 'tainted.log'
    print(f'[{bcolors.OKGREEN}+{bcolors.ENDC}] processing taint information')
    process_taint_info(input, taint_file, taint_log, dft_log_file)

    # build the loop tracing version to gather info on loop execution
    print(f'[{bcolors.OKGREEN}+{bcolors.ENDC}] building loop profiler')
    build_loop_trace(input, taint_log, optimization_level)

    # run the test suite again to gather loop information
    loop_log_file = 'loops-cfl.conf'
    print(f'[{bcolors.OKGREEN}+{bcolors.ENDC}] running loop profiler')
    run_test_suite_loop(input, loop_log_file)

    # build the constant time version of the program
    print(f'[{bcolors.OKGREEN}+{bcolors.ENDC}] building constant time version')
    build_constant_time(input, output, taint_log, loop_log_file, optimization_level)





if __name__ == '__main__':
    constantine_compile()