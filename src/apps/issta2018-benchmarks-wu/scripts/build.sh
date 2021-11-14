#!/bin/sh
set -x
set -e

file="$1" 
PROJECT_NAME=${file%.*}

# . ../../setup.sh

# DIR=`pwd`
# cd ../../passes
# make install || exit 1
# cd ../lib
# make install || exit 2

# cd $DIR
# rm -f *.bc *.ll *.S *.dot $PROJECT_NAME *.pdf
# [ "$CLEAN" = "1" ] && exit 0

dot_gen () {
  ../opt -cfg-func-name=main -cfg-dot-filename-prefix=$PROJECT_NAME -dot-cfg-only -o /dev/null $PROJECT_NAME.$1.bc 2>&1 | grep -v Writing
  dot $PROJECT_NAME.main.dot -Tpng -o $PROJECT_NAME.$1.$2.png
  rm -f $PROJECT_NAME.main.dot
}

#
# See https://github.com/SVF-tools/SVF/blob/master/lib/WPA/WPAPass.cpp
# for more pointer analysis options.
#

PA=-nander
clang -fno-exceptions -O3 -g -flto -c -o $PROJECT_NAME.base.bc $file
llvm-link -o $PROJECT_NAME.linked.bc $PROJECT_NAME.base.bc ../../bin/cfl.bcc
../opt -O3 -cgc -cgc-funcs=main -cgc-clone-prefix=__cfl_ $PA -o $PROJECT_NAME.cgc.bc $PROJECT_NAME.linked.bc
#../opt -O3 -flatten -flatten-funcs=main -flatten-icalls $PA -o $PROJECT_NAME.cgc.bc $PROJECT_NAME.linked.bc
../opt -lowerswitch -lowerinvoke -mergereturn -simplifycfg --structurizecfg  -o $PROJECT_NAME.cfgnorm.bc $PROJECT_NAME.cgc.bc
../opt -cfl -cfl-funcs=main,__cfl_.* -o $PROJECT_NAME.cfl.bc $PROJECT_NAME.cfgnorm.bc
../opt -internalize -internalize-public-api-list=main -O3 -o $PROJECT_NAME.final.bc $PROJECT_NAME.cfl.bc

dot_gen linked 01
dot_gen cgc 02
dot_gen cfgnorm 03
dot_gen cfl 04
dot_gen final 05