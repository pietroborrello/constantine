#!/bin/bash
set -e
set -x

# setup llvm env variables
cd ../..
. ./setup.sh
cd - > /dev/null

DIR=`pwd`
cd ../../passes
make install || exit 1
cd ../lib
make install || exit 2
cd $DIR

file="test.c"
cc="clang"
PROJECT_NAME=${file%.*}

OPT=${OPT:-2}

if [ $OPT -eq 0 ]; then
CFLAGS="-g -Og -mllvm -x86-cmov-converter=0 -g"
OFLAGS="-O0"
LDFLAGS="-Og -ldl"
else
CFLAGS="-O$OPT -fno-unroll-loops -mllvm -x86-cmov-converter=0 -g"
OFLAGS="-O$OPT --disable-loop-unrolling"
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
clang $CFLAGS -fPIC -DPIC -o $PROJECT_NAME.final.o -c $PROJECT_NAME.final.bc
clang $LDFLAGS -fno-exceptions -o $PROJECT_NAME.dumper.out -ldl -lm -pthread $PROJECT_NAME.final.o

# sanity check
./test.dumper.out <./random_input.txt 2>/dev/null | xxd

# execute the binary to dump the loop configuration with all random inputs in 32-bytes chunks
split -b 32 --filter='./test.dumper.out' ./random_input.txt >/dev/null 2>./loops-cfl.raw
sort ./loops-cfl.raw | uniq > ./loops-cfl.conf
rm ./loops-cfl.raw || true
}
# rm tainted.log
# rm dft.log

# dot_gen base main
# dot_gen tainted main
# dot_gen extracted main
# dot_gen final main

# for i in $PROJECT_NAME.*.bc
# do
# 	llvm-dis $i
# done