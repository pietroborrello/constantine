#!/bin/bash
set -x
trig()
{
	path="$1" 
	name=${path%.*}
	unroll=$name"_unloop.bc"
	bc=$name".bc"

	exe=$name"_exe"


	if [ "$2" ]
	then
		out=$2
	else
		out=$name".csv"
	fi

	inkey="static uint8_t in_key[24] ={"

	for i in `seq 1 23`;
	    do
	        let number=$RANDOM%256
	        inkey="$inkey$number, "
	    done 

	let number=$RANDOM%256
	inkey="$inkey$number};"

	echo $inkey
	sed -i "/static uint8_t in_key/c $inkey" $1

	clang -emit-llvm -c $1 -o $unroll
	~/llvmbuild/bin/opt -mem2reg -simplifycfg -loops -always-inline -lcssa -loop-simplify -loop-rotate -loop-unroll  $unroll -o $bc 

	llc $bc -o tmp.s
	gcc -O0 tmp.s -static -o $exe -lstdc++

	../build/X86/gem5.debug ../configs/example/se.py --cmd=$exe --cpu-type=TimingSimpleCPU --caches --cacheline_size=64 --l1d_size=32kB --l1d_assoc=512 > sim.txt

	num_miss=$(grep -m 1 "system.cpu.dcache.overall_misses::total" m5out/stats.txt | grep -o -E '[0-9]+')", "
	num_cycle=$(grep -m 1 "system.cpu.numCycles" m5out/stats.txt | grep -o -E '[0-9]+')", "

	sed -i "$(( $( wc -l < $out)))s/$/$num_cycle/" $out
	sed -i "$(( $( wc -l < $out)-1))s/$/$num_miss/" $out

	rm tmp.s $exe $unroll $bc
}


# c_benchmarks="chronos/aes   chronos/des   chronos/des3  chronos/anubis  chronos/cast5  chronos/cast6  chronos/fcrypt  chronos/khazad  
# supercop/aes_core  supercop/cast-ssl
# appliedCryp/3way appliedCryp/des appliedCryp/loki91
# libg/camellia libg/des  libg/seed  libg/twofish
# "


# botan/aes     
# botan/cast128
cpp_benchmarks=" 
botan/des 
botan/kasumi
botan/seed
botan/twofish
"

if [ "$1" ]
then
	para="$1"
	name=${para%.*}
    csv=$name".csv"
    avgFile=$1"_avg.c"
	cp $1 $avgFile
    echo > $csv
	echo "$file: #miss, " >> $csv
	echo "$file: #cycle, " >> $csv
	for i in `seq 1 100`;
    do
        trig $avgFile $csv
    done 
else
	echo > avgResult.txt
	for file in $c_benchmarks
	do
		echo "$file: #miss, " >> avgResult.txt
		echo "$file: #cycle, " >> avgResult.txt
	    name=$file"1.c"
	    avgFile=$file"_avg.c"
	    cp $name $avgFile
		for i in `seq 1 100`;
	    do
	        trig $avgFile avgResult.txt
	    done 
	    rm $avgFile
	done

	for file in $cpp_benchmarks
	do
		echo "$file: #miss, " >> avgResult.txt
		echo "$file: #cycle, " >> avgResult.txt
	    name=$file"1.cpp"
	    avgFile=$file"_avg.cpp"
	    cp $name $avgFile
		for i in `seq 1 100`;
	    do
	        trig $avgFile avgResult.txt
	    done 
	    rm $avgFile
	done
fi


