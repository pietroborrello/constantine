#!/bin/bash

cd ../..
. ./setup.sh
cd - > /dev/null

set -e
set -x

DIR=`pwd`
cd ../../passes
make install || exit 1
cd ../lib
make install || exit 2
cd $DIR

time (./build_dft.sh && ./targeted_cfl_dump_loops.sh && ./targeted_cfl.sh)

./test.orig.out < ./random_input.txt | xxd
./test.out < ./random_input.txt | xxd

taskset -c 3 perf stat -e cpu-cycles:u -r100 ./test.orig.out >/dev/null < ./random_input.txt
# taskset -c 3 perf stat -e cpu-cycles:u -r100 ./test.orig.ns.CT.out >/dev/null < ./random_input.txt
taskset -c 3 perf stat -e cpu-cycles:u -r100 ./test.out >/dev/null < ./random_input.txt

../issta2018-benchmarks-wu/scripts/trace_mem.sh ./test.out ./random_input.txt ./trace.out >/dev/null
../issta2018-benchmarks-wu/scripts/trace_mem.sh ./test.out ./random_input1.txt ./trace1.out >/dev/null
diff trace.out trace1.out