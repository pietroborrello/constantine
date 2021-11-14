#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <binary> callgrind.out.<pid>"
    echo "Will create 'callgrind.out.<pid>.patched' taking symbols from <binary>"
    exit 1
fi

binary=$1
cg_file=$2
output_file="$cg_file.patched"
echo "Writing $output_file"

cp $cg_file $output_file
nm --defined-only $binary | grep -i ' t ' | while read line; do
    read addr t name <<<$line
    echo "ADDR: 0x$addr NAME: $name"
    sed -i "s/0x$addr/$name/g" $output_file
done;
