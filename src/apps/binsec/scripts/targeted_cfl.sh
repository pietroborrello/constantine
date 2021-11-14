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

file="$1"
cc="clang"
PROJECT_NAME=${file%.*}
LIBNAME="binsec"

OPT=${OPT:-2}
DFL_AVX=${DFL_AVX:-"-dfl-avx2=1"}
NOAVX=${NOAVX:-""}
AVX_VER=${AVX_VER:-""}

if [ $OPT -eq 0 ]; then
CFLAGS="-g -Og -mllvm -x86-cmov-converter=0 -g"
OFLAGS="-O0"
LDFLAGS="-Og -ldl"
else
CFLAGS="-O$OPT -fno-unroll-loops -mllvm -x86-cmov-converter=0 -g -fno-delete-null-pointer-checks $NOAVX"
OFLAGS="-O$OPT"
LDFLAGS="-O$OPT -ldl"
fi

dot_gen () {
  opt -cfg-func-name=$2 -cfg-dot-filename-prefix=$PROJECT_NAME.$1 -dot-cfg -o /dev/null $PROJECT_NAME.$1.bc
}

{
# USE SAME INPUT.BC AS BUILD_DFT.SH
cut -f2,3,4 -d':' --output-delimiter=' ' -s dft.log > tainted.log
../opt -loadtainted -tainted-file=tainted.log -o $PROJECT_NAME.tainted.bc $PROJECT_NAME.coverage-id.bc

../opt -internalize -internalize-public-api-list=main -globaldce -remove-dup-lifetimes -set-norecurse-ext -functionattrs -rpo-functionattrs -forward-geps -mark-induction-variables -mark-only-simple-vars=0 -convert-ptr-to-indexes -taint-stats -branch-extract -branch-extract-funcs='.*' -o $PROJECT_NAME.extracted.bc $PROJECT_NAME.tainted.bc

# clone all calls to make them unique and make SVF more precise even if context insensitive
../opt -cgc -cgc-funcs='__cfl_.*' -cgc-clone-prefix='__cfl_' -cgc-icalls=0 -cgc-unique -internalize -internalize-public-api-list=main -globaldce -o $PROJECT_NAME.cgc.bc $PROJECT_NAME.extracted.bc

../opt -functionattrs -rpo-functionattrs -stack-vars-promotion -stack-vars-promotion-funcs='.*' -stack-vars-promotion-cfl-funcs='__cfl_.*' -stat=0 -modelConsts -allow-fi-prom=0 -fieldlimit=4294967295 -o $PROJECT_NAME.promoted.bc $PROJECT_NAME.cgc.bc
llvm-link -o $PROJECT_NAME.linked_2.bc $PROJECT_NAME.promoted.bc ../../bin/cfl$AVX_VER.bcc ../../bin/dfl$AVX_VER.bcc
../opt -dfl -dfl-funcs='.*' -dfl-cfl-funcs='__cfl_.*' $DFL_AVX -dfl-induction-vars=1 -stat=0 -modelConsts -allow-fi-prom=0 -fieldlimit=4294967295 -o $PROJECT_NAME.dfl.bc $PROJECT_NAME.linked_2.bc

../opt -cfl -cfl-funcs='__cfl_.*' -cfl-protect-mem=0 -cfl-protect-branches=1 -o $PROJECT_NAME.cfl.bc $PROJECT_NAME.dfl.bc
../opt -loops -loop-simplify -lcssa -loops-cfl -loops-cfl-funcs='__cfl_.*' -loops-cfl-protect-stores=1 -loops-cfl-conf='./loops-cfl.conf' -o $PROJECT_NAME.loops-cfl.bc $PROJECT_NAME.cfl.bc
../opt -hook -hook-funcs='__cfl_.*' -o $PROJECT_NAME.div.bc $PROJECT_NAME.loops-cfl.bc
../opt -internalize -internalize-public-api-list=main -fix-callsite-attrs $OFLAGS -o $PROJECT_NAME.final.bc $PROJECT_NAME.div.bc
clang $CFLAGS -fPIC -DPIC -o $PROJECT_NAME.final.o -c $PROJECT_NAME.final.bc
clang $LDFLAGS -fno-exceptions -o $PROJECT_NAME.out -ldl -lm -pthread $PROJECT_NAME.final.o
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