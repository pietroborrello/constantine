#!/bin/bash
set -e
set -x

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

dot_gen () {
  ../opt -cfg-func-name=main -cfg-dot-filename-prefix=$PROJECT_NAME.$1 -dot-cfg -o /dev/null $PROJECT_NAME.$1.bc 2>&1 | grep -v Writing
}

clang $CFLAGS -flto -c -o $PROJECT_NAME.base.bc $file -fno-exceptions
llvm-link -o $PROJECT_NAME.linked.bc $PROJECT_NAME.base.bc
../opt $OFLAGS -o $PROJECT_NAME.opt.bc $PROJECT_NAME.linked.bc
../opt -scalarizer -scalarize-load-store -lowerswitch -lowerinvoke -loop-simplify -mergereturn  -mem2reg -simplifycfg -structurizecfg -o $PROJECT_NAME.cfgnorm.bc $PROJECT_NAME.opt.bc
../opt -coverage-id -coverage-id-b-gids -coverage-id-i-bids -o $PROJECT_NAME.coverage-id.bc $PROJECT_NAME.cfgnorm.bc
cut -f2,3,4 -d':' --output-delimiter=' ' -s dft.log > tainted.log
../opt -loadtainted -tainted-file=tainted.log -o $PROJECT_NAME.tainted.bc $PROJECT_NAME.coverage-id.bc
rm tainted.log
dot_gen base
dot_gen tainted

../opt -functionattrs -stack-vars-promotion -stack-vars-promotion-funcs='.*' -stat=0 -modelConsts -o $PROJECT_NAME.promoted.bc $PROJECT_NAME.tainted.bc
llvm-link -o $PROJECT_NAME.linked_dfl.bc $PROJECT_NAME.promoted.bc ../../bin/dfl.bcc
../opt -dfl -dfl-funcs='.*' -stat=0 -modelConsts -o $PROJECT_NAME.dfl.bc $PROJECT_NAME.linked_dfl.bc
dot_gen dfl

# ../opt -branch-extract -o $PROJECT_NAME.extracted.bc $PROJECT_NAME.tainted.bc

# llvm-link -o $PROJECT_NAME.linked_2.bc $PROJECT_NAME.extracted.bc ../../bin/cfl.bcc
# ../opt -cgc -cgc-funcs='__cfl_.*' -cgc-clone-prefix='__cfl_' -nander -o $PROJECT_NAME.cgc.bc $PROJECT_NAME.linked_2.bc
# ../opt -scalarizer -scalarize-load-store -cfl -cfl-funcs='__cfl_.*' -o $PROJECT_NAME.cfl.bc $PROJECT_NAME.cgc.bc
# ../opt -loops -loop-simplify -loops-cfl -loops-cfl-funcs='__cfl_.*' -o $PROJECT_NAME.loops-cfl.bc $PROJECT_NAME.cfl.bc
../opt -internalize -internalize-public-api-list=main $OFLAGS -o $PROJECT_NAME.final.bc $PROJECT_NAME.dfl.bc
# rm dft.log

# dot_gen extracted
# dot_gen final

for i in $PROJECT_NAME.*.bc
do
	llvm-dis $i
done