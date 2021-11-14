set -x
set -e

file="$1" 
name=${file%.*}
unroll=$name"_unloop.bc"
bc=$name".bc"
out=$name"_out.bc"
outopt=$name"_out_opt.bc"
tmps=$name".s"
exeorig=$name"_orig_exe"
exe=$name"_exe"
exeopt=$name"_opt_exe"

echo "Test for file $1\n"
echo "generate bc file:"
clang -emit-llvm -c $1 -o $unroll
opt -mem2reg -simplifycfg -loops -always-inline -lcssa -loop-simplify -loop-rotate -loop-unroll  $unroll -o $bc 

#rm -f $unroll
llvm-dis < $unroll > $name"_unloop.ll"
llvm-dis < $bc > "$name.ll"

opt -O1 < $bc > $out
opt -O3 < $bc > $outopt
echo -e "original file size:"
stat --printf="%s" $bc
echo -e "\nwo opt file size:"
stat --printf="%s" $out
echo -e "\nwith opt file size:"
stat --printf="%s" $outopt
echo ""
