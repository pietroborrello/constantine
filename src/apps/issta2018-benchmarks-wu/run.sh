#!/bin/bash
set -x
set -e

cd ../..
. ./setup.sh
cd - > /dev/null

run()
{
simout=sim.txt
if [ "$3" ]
then
    simout=$3
fi
taskset -c 3 perf stat -e cpu-cycles:u -x',' -r100 ./$1 <random_input.txt 2>&1 >$simout | cut -f 1 -d, > run.txt
}

armcompile()
{
llc -march=arm $1 -o tmp.s
arm-linux-gnueabi-gcc -O0 tmp.s -static -o $2
rm tmp.s
}

# x86compile()
# {
# llc -O3 $1 -o tmp.S
# $3 -O3 tmp.S -o $2
# }

x86compile()
{
../opt -internalize -internalize-public-api-list=main -O3 -o tmp.bc $1
$3 -fno-exceptions -O3 tmp.bc -ldl -o $2
rm tmp.bc
}

runonfile()
{	
	if [ "$2" ]
	then
		file1="examples/"$1".cpp"
		cc="clang++"
	else
		file1="examples/"$1".c"
		cc="clang"
	fi

	base="examples/"$1
	name="examples/"${1%.*}
	stat=$base".txt"

	bc1=$name".base.bc"

	out1=$name".final.bc"

	exeorig1=$name".orig.out"
	exe1=$name".out"
	./scripts/build.sh $file1

	bc_size=$(stat --printf="%s" $bc1 | grep -o -E '[0-9]+')
	outbc_size=$(stat --printf="%s" $out1 | grep -o -E '[0-9]+')

	x86compile $bc1 $exeorig1 $cc
	run $exeorig1 $stat orig_output.txt
	orig1_num_cycle=$(grep -o -E '[0-9]+' run.txt)

	x86compile $out1 $exe1 $cc
	run $exe1 $stat output.txt
	out1_num_cycle=$(grep -o -E '[0-9]+' run.txt)

	rm sim.txt || true
	rm run.txt
	diff orig_output.txt output.txt || (echo "ERROR: output mismatch for "$1; exit 1;)
	rm orig_output.txt output.txt

	../../utils/verifier/analyze-cfg.py $exe1 main
	# ../../utils/verifier/verifier.py $exe1 main

	echo $1", "$bc_size", "$outbc_size", "$orig1_num_cycle", "$out1_num_cycle", "$(LC_ALL=C printf "%.3f\n" "$(bc -l <<<$outbc_size/$bc_size)")", "$(LC_ALL=C printf "%.3f\n" "$(bc -l <<<$out1_num_cycle/$orig1_num_cycle)") >>result.csv
}


c_benchmarks="chronos/aes   chronos/des   chronos/des3  chronos/anubis  chronos/cast5  chronos/cast6  chronos/fcrypt  chronos/khazad  
supercop/aes_core  supercop/cast-ssl
appliedCryp/3way appliedCryp/des appliedCryp/loki91
libg/camellia libg/des  libg/seed  libg/twofish
"

cpp_benchmarks="botan/aes
botan/cast128 botan/des 
botan/kasumi
botan/seed
botan/twofish
"

echo "DISABLING perf_event_paranoid"
echo '-1' | sudo tee /proc/sys/kernel/perf_event_paranoid 

if [ "$1" ]
then
	runonfile $1 $2
else
	echo "filename, orig_size, final_size, orig1_num_cycle, out1_num_cycle, size_overhead, cycles_overhead" > result.csv
	for file in $c_benchmarks
	do
	    runonfile $file
	done
	for file in $cpp_benchmarks
	do
	    runonfile $file cpp
	done
	for i in examples/*/*.bc
	do
		llvm-dis $i
	done
fi
