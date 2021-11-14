#!/bin/sh

# make sure to have a recent objcopy version in the PATH (like 2.35)

set -e
set -x

# setup llvm env variables
cd ../..
. ./setup.sh
cd - > /dev/null

# clone the repo and checkout the right branch
cd ..
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
git checkout v4.5.0-stable
git am -3 -k ../wolfssl_case_study/wolfssl.patch
./autogen.sh
