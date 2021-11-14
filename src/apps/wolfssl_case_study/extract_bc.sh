#!/bin/sh

# make sure to have a recent objcopy version in the PATH (like 2.35)

set -e
set -x

# setup llvm env variables
cd ../..
. ./setup.sh
cd - > /dev/null

export LLVM_BITCODE_GENERATION_FLAGS="-flto"
# install the library so that we have the headers easily available
cd ../wolfssl
rm -r ./autom4te.cache
./autogen.sh
CC=clang CXX=clang++ CFLAGS="-DWOLFSSL_DEBUG_MATH -DFP_MAX_BITS=256 -g -Xclang -disable-llvm-passes" ./configure --disable-harden --disable-dh --enable-ecc --disable-asm --disable-memory
make
sudo make install
make clean

# configure to use gllvm (https://github.com/SRI-CSL/gllvm)
WLLVM_CONFIGURE_ONLY=1 CC=gclang CXX=gclang++ CFLAGS="-DWOLFSSL_DEBUG_MATH -DFP_MAX_BITS=256 -g -Xclang -disable-llvm-passes" ./configure --disable-harden --disable-dh --enable-ecc --disable-asm --disable-memory
make
# extract the bytecode
get-bc -b -o wolfssl.bc ./src/.libs/libwolfssl.so.24.2.0

# copy the generated files
cp wolfssl.bc ../wolfssl_case_study
cd ../wolfssl_case_study
llvm-dis wolfssl.bc

# test it recompiles
clang -shared -fPIC -DPIC wolfssl.bc -lm -pthread -O2 -pthread -Wl,-soname -Wl,libwolfssl.so.24 -o ./libwolfssl.so.24.2.0