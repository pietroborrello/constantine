#!/bin/bash

set -e
set -x

. ./setup.sh

cd llvm-9
git apply ../0001-Add-support-to-build-libcxx-and-libcxxabi-with-DFSan.patch 

mkdir $LLVM_SRC/build-dfsan
cd $LLVM_SRC/build-dfsan

cmake -G Ninja ../llvm \
       -DLLVM_LIBDIR_SUFFIX=64 \
        -DLLVM_ENABLE_PROJECTS='libcxx;libcxxabi' \
        -DLLVM_USE_SANITIZER=DataFlow \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_C_FLAGS='-fsanitize-blacklist=/usr/lib/llvm-9/lib/clang/9.0.0/share/dfsan_abilist.txt' \
        -DCMAKE_CXX_FLAGS='-fsanitize-blacklist=/usr/lib/llvm-9/lib/clang/9.0.0/share/dfsan_abilist.txt' \
        -DLIBCXX_ENABLE_SHARED=OFF \
        -DLIBCXXABI_ENABLE_SHARED=OFF

ninja cxx cxxabi
