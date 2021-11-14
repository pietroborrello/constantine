#!/bin/sh
set -e
set -x

file="$1"
cc="$2"
cflags="$3"
ldflags="$4"
PROJECT_NAME=${file%.*}

OPT=${OPT:-3}

if [ $OPT -eq 0 ]; then
CFLAGS="-g -Og "
OFLAGS="-O0"
LDFLAGS="-Og "$ldflags
else
CFLAGS="-O$OPT "
OFLAGS="-O$OPT"
LDFLAGS="-O$OPT "$ldflags
fi

DFSAN_ABILIST=`$cc $cflags -fsanitize=dataflow -c $file -### 2>&1 | grep sanitize | sed "s/.*-fsanitize-blacklist=\([^\"]*\).*/\1/g"`

cat $DFSAN_ABILIST ../../lib/dft/dfsan.abilist > dfsan_abilist.txt

# N.B. all the files will have a 1 before .ext, due to how is computed PROJECT_NAME
clang $CFLAGS $cflags -flto -c -o $PROJECT_NAME.base.bc $file
llvm-link -o $PROJECT_NAME.linked.bc $PROJECT_NAME.base.bc
../opt $OFLAGS -o $PROJECT_NAME.opt.bc $PROJECT_NAME.linked.bc
../opt -lowerswitch -lowerinvoke -loop-simplify -mergereturn -simplifycfg --structurizecfg -o $PROJECT_NAME.cfgnorm.bc $PROJECT_NAME.opt.bc
../opt -coverage-id -coverage-id-b-gids -coverage-id-i-bids -o $PROJECT_NAME.coverage-id.bc $PROJECT_NAME.cfgnorm.bc
cut -f2,3,4 -d':' --output-delimiter=' ' -s dft.log > tainted.log
../opt -loadtainted -tainted-file=tainted.log -o $PROJECT_NAME.tainted.bc $PROJECT_NAME.coverage-id.bc
../opt -lowerinvoke -loop-simplify -dumptaintedloops -dump-file=loops.log -o /dev/null $PROJECT_NAME.tainted.bc
rm tainted.log
