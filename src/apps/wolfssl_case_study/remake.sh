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