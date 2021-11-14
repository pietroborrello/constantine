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

OPT=${OPT:-3}

if [ $OPT -eq 0 ]; then
CFLAGS="-g -Og"
OFLAGS="-O0"
LDFLAGS="-Og "$ldflags
else
CFLAGS="-O$OPT -mllvm -x86-cmov-converter=0 "
OFLAGS="-O$OPT"
LDFLAGS="-O$OPT "$ldflags
fi

dot_gen () {
    opt -cfg-func-name=$2 -cfg-dot-filename-prefix=test.$1 -dot-cfg -o /dev/null test.$1.bc 2>&1
}

png_gen () {
    opt -disable-verify -cfg-func-name=$2 -cfg-dot-filename-prefix=$1 -dot-cfg -o /dev/null $1.bc || return 0
    dot $1.$2.dot -Tpng -o $1.png
    rm $1.$2.dot
}

DFSAN_ABILIST=`$cc $cflags -fsanitize=dataflow -c $file -### 2>&1 | grep sanitize | sed "s/.*-fsanitize-blacklist=\([^\"]*\).*/\1/g"`

cat $DFSAN_ABILIST ../../lib/dft/dfsan.abilist > dfsan_abilist.txt

clang $CFLAGS -flto -c -o test.base.bc test.c
llvm-link -o test.linked.bc test.base.bc wolfssl.bc 
opt $OFLAGS  -loops -loop-simplify -o test.loop.bc test.linked.bc
opt -simplifycfg -o test.simplified.bc test.loop.bc
../opt -fix-irreducible -unify-loop-exits -custom-structurizecfg -o test.cfgnorm.bc test.simplified.bc

clang $CFLAGS -fPIC -o test.cfgnorm.out -lm -pthread test.cfgnorm.bc
clang $CFLAGS -fPIC -o test.linked.out -lm -pthread test.linked.bc

dot_gen base my2_fp_div_d
dot_gen loop my2_fp_div_d
dot_gen cfgnorm my2_fp_div_d
dot_gen cfgnorm my_s_is_power_of_two
dot_gen simplified my2_fp_div_d
dot_gen simplified my_s_is_power_of_two

# for f in dumps/*.bc
# do
#     m=${f%.*}
#     png_gen $m my2_fp_div_d
# done
# mv dumps/*.png pngs/
./test.cfgnorm.out < random_input.txt

# for i in $PROJECT_NAME.*.bc
# do
# 	llvm-dis $i
# done
