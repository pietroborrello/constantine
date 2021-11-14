#!/bin/sh

set -e
export MAKEFLAGS="-j $(grep -c ^processor /proc/cpuinfo)"

BINUTILS_VERSION=${BINUTILS_VERSION:-2.31.90}
LLVM_VERSION=${LLVM_VERSION:-9}

#
# Binutils
#
wget ftp://sourceware.org/pub/binutils/snapshots/binutils-${BINUTILS_VERSION}.tar.xz
tar xvfJ binutils-${BINUTILS_VERSION}.tar.xz
rm -f binutils-${BINUTILS_VERSION}.tar.xz
cd binutils-${BINUTILS_VERSION}
mkdir binutils-objects
cd binutils-objects
../configure --enable-gold --enable-plugins
make all-gold
cd ../..

#
# LLVM (release mode)
#
git clone https://github.com/llvm/llvm-project.git llvm-${LLVM_VERSION}
cd llvm-${LLVM_VERSION}
git checkout release/${LLVM_VERSION}.x
git am -3 -k ../LoopInfo_TopLevelLoops.patch
mkdir bin && mkdir debug_bin && mkdir llvm-objects && mkdir llvm-objects-debug
cd llvm-objects
cmake ../llvm -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS=clang\;lld\;compiler-rt -DLLVM_EXTERNAL_CLANG_SOURCE_DIR=`pwd`/../clang -DLLVM_EXTERNAL_LLD_SOURCE_DIR=`pwd`/../lld -DLLVM_EXTERNAL_COMPILERRT_SOURCE_DIR=`pwd`/../compiler-rt -DLLVM_REQUIRES_RTTI=ON -DLLVM_ENABLE_ASSERTIONS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=`pwd`/../bin/ -DLLVM_BINUTILS_INCDIR=`pwd`/../../binutils-${BINUTILS_VERSION}/include/
make && make install
cd ../..

#
# Setup script
#
echo > setup.sh
chmod +x setup.sh
echo '#!/bin/sh'                                                    >> setup.sh
echo 'LLVM_VERSION=${LLVM_VERSION:-'${LLVM_VERSION}'}'              >> setup.sh
echo 'export LLVM_SRC=`pwd`/llvm-${LLVM_VERSION}'                   >> setup.sh
echo 'export LLVM_OBJ=$LLVM_SRC/llvm-objects'                       >> setup.sh
echo 'export LLVM_DIR=$LLVM_OBJ'                                    >> setup.sh
echo 'export SVF_HOME=`pwd`/SVF'                                    >> setup.sh
echo 'export PATH=$LLVM_DIR/bin:$SVF_HOME/Debug-build/bin:$PATH'    >> setup.sh

#
# SVF
#
. ./setup.sh
git clone https://github.com/SVF-tools/SVF.git SVF
cd SVF
git checkout SVF-1.9
git am -3 -k ../SVF-model-const.patch
git am -3 -k ../SVF-Field-Sensitivity.patch

mkdir Debug-build
cd Debug-build
cmake -D CMAKE_BUILD_TYPE:STRING=Debug ../
make

echo "Use . ./setup.sh to set up your environment."
