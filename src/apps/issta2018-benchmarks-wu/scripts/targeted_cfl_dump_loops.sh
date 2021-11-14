#!/bin/bash
set -e
set -x
set -u

file="$1"
cc="$2"
PROJECT_NAME=${file%.*}

OPT=${OPT:-2}

if [ $OPT -eq 0 ]; then
CFLAGS="-g -Og -mllvm -x86-cmov-converter=0 -g"
OFLAGS="-O0"
LDFLAGS="-Og -ldl"
else
CFLAGS="-O$OPT -fno-unroll-loops -mllvm -x86-cmov-converter=0 -g"
OFLAGS="-O$OPT"
LDFLAGS="-O$OPT -ldl"
fi

dot_gen () {
  opt -cfg-func-name=$2 -cfg-dot-filename-prefix=$PROJECT_NAME.$1 -dot-cfg -o /dev/null $PROJECT_NAME.$1.bc
}

{
# USE SAME INPUT.BC AS BUILD_DFT.SH
cut -f2,3,4 -d':' --output-delimiter=' ' -s dft.log > tainted.log
../opt -loadtainted -tainted-file=tainted.log -check-undefined -o $PROJECT_NAME.tainted.bc $PROJECT_NAME.coverage-id.bc

../opt -internalize -internalize-public-api-list=main -globaldce -remove-dup-lifetimes -set-norecurse-ext -functionattrs -rpo-functionattrs -forward-geps -branch-extract -branch-extract-funcs='.*' -check-undefined -o $PROJECT_NAME.extracted.bc $PROJECT_NAME.tainted.bc

../opt -cgc -cgc-funcs='__cfl_.*' -cgc-clone-prefix='__cfl_' -cgc-icalls=0 -cgc-unique -internalize -internalize-public-api-list=main -globaldce -check-undefined -o $PROJECT_NAME.cgc.bc $PROJECT_NAME.extracted.bc

llvm-link -o $PROJECT_NAME.linked_2.bc $PROJECT_NAME.cgc.bc ../../bin/cfl.bcc ../../bin/dfl.bcc

../opt -loops -loop-simplify -lcssa -loops-cfl -loops-cfl-funcs='__cfl_.*' -loops-cfl-dump-conf -check-undefined -o $PROJECT_NAME.loops-cfl.bc $PROJECT_NAME.linked_2.bc
../opt -internalize -internalize-public-api-list=main -fix-callsite-attrs $OFLAGS -check-undefined -o $PROJECT_NAME.final.bc $PROJECT_NAME.loops-cfl.bc
$cc $CFLAGS -fPIC -DPIC -o $PROJECT_NAME.final.o -c $PROJECT_NAME.final.bc
$cc $LDFLAGS -fno-exceptions -o $PROJECT_NAME.dumper.out $PROJECT_NAME.final.o

# sanity check
./$PROJECT_NAME.dumper.out <./random_input.txt 2>/dev/null | xxd

# execute the binary to dump the loop configuration with all random inputs in 128-bytes chunks
split -b 128 --filter="./$PROJECT_NAME.dumper.out | xxd" ./random_input.txt >/dev/null 2>./loops-cfl.raw
sort ./loops-cfl.raw | uniq > ./loops-cfl.conf
rm ./loops-cfl.raw || true
}