#!/bin/sh

# make sure to have a recent objcopy version in the PATH (like 2.35)

set -e
set -x

# setup llvm env variables
cd ../../..
. ./setup.sh
cd - > /dev/null

export LLVM_BITCODE_GENERATION_FLAGS="-flto"
# install the library so that we have the headers easily available
cd BearSSL
make CONF=gclang
# extract the bytecode
rm bearssl.bc
get-bc -b -o bearssl.bc build/libbearssl.a

# copy the generated files
cp bearssl.bc ../
llvm-dis bearssl.bc
