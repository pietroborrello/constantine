#!/bin/sh
set -e
set -x

# setup llvm env variables
cd ../..
. ./setup.sh
cd - > /dev/null

file="$1"
PROJECT_NAME=${file%.*}

OPT=${OPT:-3}

if [ $OPT -eq 0 ]; then
CFLAGS="-g -Og -mllvm -x86-cmov-converter=0"
OFLAGS="-O0"
LDFLAGS="-Og -ldl"
else
CFLAGS="-O$OPT -mllvm -x86-cmov-converter=0"
OFLAGS="-O$OPT"
LDFLAGS="-O$OPT -ldl"
fi

clang $CFLAGS -flto -c -o test.base.bc test.c -fno-exceptions
llvm-link -o test.linked.bc test.base.bc wolfssl.bc
llvm-dis test.linked.bc
clang -fPIC -DPIC test.linked.bc -lm -pthread $LDFLAGS -o ./test

taskset -c 3 perf stat -e cpu-cycles:u -r100 ./test >/dev/null < random_input.txt