#!/bin/bash

file=$1
function=$2

gdb -batch -ex "file $file" -ex "disassemble $function" | grep j | while read -r jmp; do
    jmp_location=$(echo $jmp | cut -f1 -d' ');
    jmp_target=$(echo $jmp | cut -f4 -d' ');
    echo "$jmp_location -> $jmp_target: offset" $(($jmp_target - $jmp_location))
done;
