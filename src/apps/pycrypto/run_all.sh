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
# generate all the libs we need to use the different versions
ARCH='westmere' make clean install || exit 2
cp ../bin/cfl.bcc ../bin/cfl.noavx.bcc
cp ../bin/dfl.bcc ../bin/dfl.noavx.bcc
ARCH='skylake-avx512' make clean install || exit 2
cp ../bin/cfl.bcc ../bin/cfl.avx512.bcc
cp ../bin/dfl.bcc ../bin/dfl.avx512.bcc
ARCH='native' make clean install || exit 2
cd $DIR

OPT=${OPT:-3}

simulate()
{
export GEM5_PATH="/home/one/Programs/gem5"
$GEM5_PATH/build/X86/gem5.opt $GEM5_PATH/configs/example/se.py --cmd=$1 --input=$2 --cpu-type=TimingSimpleCPU --caches --cacheline_size=64 --l1d_size=32kB --l1d_assoc=512 >/dev/null 2>&1
echo -e "Simulation for file $1:\n"

# grep -m 1 "system.cpu.committedInsts " m5out/stats.txt
# grep -m 1 "system.cpu.icache.overall_hits::total" m5out/stats.txt
# grep -m 1 "system.cpu.icache.overall_misses::total" m5out/stats.txt
# grep -m 1 "system.cpu.dcache.overall_hits::total" m5out/stats.txt
# grep -m 1 "system.cpu.dcache.overall_misses::total" m5out/stats.txt
grep -m 1 "system.cpu.numCycles" m5out/stats.txt
}

run_perf()
{
taskset -c 3 perf stat -e cpu-cycles:u -x',' -r2000 ./$1 <random_input.txt 2>&1 >/dev/null | cut -f 1 -d, > run.txt
}

run_noperf()
{
simout=sim.txt
if [ "$2" ]
then
	simout=$2
fi
./$1 <random_input.txt >$simout
}

x86compile()
{
../opt -internalize -internalize-public-api-list=main -O$OPT -o tmp.bc $1
$3 -mllvm -x86-cmov-converter=0 -O$OPT tmp.bc -ldl -o $2 -fno-exceptions
rm tmp.bc
}

trace_instrs()
{
valgrind --tool=cachegrind --cachegrind-out-file=/tmp/cachegrind.out ./$1 < ./$2 |& grep -a 'I   refs:' | cut -d: -f2 > $3
cat $3
}

runonfile()
{
	file1="src/"$1".c"
	cc="clang"
	cflags=""
	ldflags=""
	base="src/"$1
	name=${file1%.*}
	output=$name".taint"
	exeorig1=$name".orig.out"
	exe1=$name".out"
	noavxexe1=$name".noavx.out"
	avx512exe1=$name".avx512.out"
	stat=$base".txt"
	bc1=$name".base.bc"
	out1=$name".final.bc"

	# compile orig and dft versions
	dft_start=$(date +%s%3N)
	OPT=$OPT ./scripts/build_dft.sh $file1 $cc "$cflags" "$ldflags"
	dft_end=$(date +%s%3N)

	OPT=$OPT ./scripts/targeted_cfl_dump_loops.sh $file1 $cc

	# no AVX version for gem5
	OPT=$OPT DFL_AVX=" " NOAVX="-mno-avx -mno-sse -mno-avx2" AVX_VER=".noavx" ./scripts/targeted_cfl.sh $file1 $cc
	mv $exe1 $noavxexe1

	# AVX512 version for our server
	OPT=$OPT DFL_AVX="-dfl-avx512=1" NOAVX="-march=skylake-avx512" AVX_VER=".avx512" ./scripts/targeted_cfl.sh $file1 $cc
	mv $exe1 $avx512exe1

	# AVX version for our lovely perf
	lin_start=$(date +%s%3N)
	OPT=$OPT ./scripts/targeted_cfl.sh $file1 $cc > stats.txt
	lin_end=$(date +%s%3N)

	# read stats
	protected_branches=$(grep -m 1 "\[+\] Linearized Branches:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	protected_loops=$(grep -m 1 "\[+\] Protected Loops:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	protected_reads=$(grep -m 1 "\[+\] Protected Reads:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	protected_writes=$(grep -m 1 "\[+\] Protected Writes:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	tainted_branches=$(grep -m 1 "\[+\] Tainted Branches:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	tainted_loops=$(grep -m 1 "\[+\] Tainted Loops:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	tainted_reads=$(grep -m 1 "\[+\] Tainted Reads:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	tainted_writes=$(grep -m 1 "\[+\] Tainted Writes:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	total_branches=$(grep -m 1 "\[+\] Tot Branches:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	total_loops=$(grep -m 1 "\[+\] Tot Loops:" stats.txt | grep -o -E '[0-9]+' || echo '0')
	total_accesses=$(grep -m 1 "\[+\] Total Accesses:" stats.txt | grep -o -E '[0-9]+' || echo '0')

	run_noperf $exeorig1 orig_output.txt
	run_noperf $exe1 output.txt
	diff orig_output.txt output.txt || (echo "ERROR: output mismatch for "$1; exit 1;)
	rm orig_output.txt output.txt
	
	run_perf $exeorig1
	orig1_num_cycle=$(grep -o -E '[0-9]+' run.txt)

	run_perf $exe1
	out1_num_cycle=$(grep -o -E '[0-9]+' run.txt)

	# rm sim.txt || true
	# rm run.txt

	./scripts/trace_mem.sh $noavxexe1 ./random_input.txt ./trace.out >/dev/null
	./scripts/trace_mem.sh $noavxexe1 ./random_input2.txt ./trace1.out >/dev/null
	diff ./trace.out ./trace1.out || (echo "ERROR: linearization mismatch for "$1; exit 1;)
	rm ./trace.out ./trace1.out

	./scripts/trace_mem.sh $exe1 ./random_input.txt ./trace.out >/dev/null
	./scripts/trace_mem.sh $exe1 ./random_input2.txt ./trace1.out >/dev/null
	diff ./trace.out ./trace1.out || (echo "ERROR: AVX linearization mismatch for "$1; exit 1;)
	rm ./trace.out ./trace1.out

	trace_instrs $noavxexe1 ./random_input.txt ./trace.out
	trace_instrs $noavxexe1 ./random_input2.txt ./trace1.out
	diff ./trace.out ./trace1.out || (echo "ERROR: instruction linearization mismatch for "$1; exit 1;)
	rm ./trace.out ./trace1.out

	trace_instrs $exe1 ./random_input.txt ./trace.out
	trace_instrs $exe1 ./random_input2.txt ./trace1.out
	diff ./trace.out ./trace1.out || (echo "ERROR: AVX instruction linearization mismatch for "$1; exit 1;)
	rm ./trace.out ./trace1.out

	simulate $exeorig1 ./random_input.txt
	gemorig_num_cycle=$(grep -m 1 "system.cpu.numCycles" m5out/stats.txt | grep -o -E '[0-9]+')

	simulate $noavxexe1 ./random_input.txt
	gem_num_cycle=$(grep -m 1 "system.cpu.numCycles" m5out/stats.txt | grep -o -E '[0-9]+')

	strip $exeorig1
	strip $noavxexe1
	strip $exe1
	# strip $avx512exe1

	#measure load time
	load_orig=$(taskset -c 3 ./scripts/measure_ld_time.py $exeorig1)
	load=$(taskset -c 3 ./scripts/measure_ld_time.py $exe1)

	orig_size=$(stat --printf="%s" $exeorig1 | grep -o -E '[0-9]+')
	noavx_size=$(stat --printf="%s" $noavxexe1 | grep -o -E '[0-9]+')
	avx2_size=$(stat --printf="%s" $exe1 | grep -o -E '[0-9]+')
	# avx512_size=$(stat --printf="%s" $avx512exe1 | grep -o -E '[0-9]+')

	echo $1", "$orig_size", "$avx2_size", "$orig1_num_cycle", "$out1_num_cycle", "$(LC_ALL=C printf "%.3f\n" "$(bc -l <<<$avx2_size/$orig_size)")", "$(LC_ALL=C printf "%.3f\n" "$(bc -l <<<$out1_num_cycle/$orig1_num_cycle)")", "$(LC_ALL=C printf "%.3f\n" "$(bc -l <<<$gem_num_cycle/$gemorig_num_cycle)")", "$tainted_branches", "$tainted_loops", "$tainted_reads", "$tainted_writes", "$protected_branches", "$protected_loops", "$protected_reads", "$protected_writes", "$(($dft_end - $dft_start))", "$(($lin_end - $lin_start))", "$(LC_ALL=C printf "%.3f\n" "$(bc -l <<<$load/$load_orig)")", "$total_branches", "$total_loops", "$total_accesses>>result.csv
}

c_benchmarks="AES ARC2 ARC4 Blowfish CAST DES DES3 XOR"

if [[ $(< /proc/sys/kernel/perf_event_paranoid ) != "-1" ]]; then
	echo "DISABLING perf_event_paranoid"
	echo '-1' | sudo tee /proc/sys/kernel/perf_event_paranoid 
fi

if [[ $(< /proc/sys/kernel/randomize_va_space ) != "0" ]]; then
	echo "DISABLING ASLR to check linearized accesses"
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
fi

if [ "$1" ]
then
	runonfile $1 $2
else
	mv result.csv result.csv.bak || true
	./scripts/clean.sh || true
	echo "filename, orig_size, final_size, orig1_num_cycle, out1_num_cycle, size_overhead, cycles_overhead, gemcycles_overhead (no AVX), tainted_branches, tainted_loops, tainted_reads, tainted_writes, protected_branches, protected_loops, protected_reads, protected_writes, testing time (ms), linearization time (ms), load time ratio, total branches, total loops, total accesses" > result.csv
	for file in $c_benchmarks
	do
		runonfile $file
	done
	./stats.py result.csv
fi