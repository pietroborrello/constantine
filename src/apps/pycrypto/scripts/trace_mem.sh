#!/bin/bash
set -e
set -x
set -u

file="$1"
input="$2"
output="$3"

cp $input ./pin_input
$PIN_ROOT/pin -t ../../utils/pintool/obj-intel64/memory-check.so -o ./pin_trace -- $file < ./pin_input
cp ./pin_trace $output