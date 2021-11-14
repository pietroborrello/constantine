#!/bin/bash
# set -x
set -u
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <file.bc>"
    exit 1
fi

bc_file=$1
dot_file="${bc_file/.bc/}.dot"
list_file="${bc_file/.bc/}.function.list"

../opt --dot-callgraph -o /dev/null $bc_file
mv callgraph.dot $dot_file
echo "Moved to '$dot_file'"

../opt -list-tainted-funcs -list-as-tainted="__cfl_.*" -list-out-file="$list_file" -o /dev/null $bc_file
$DIR/view_dot.sh $dot_file $list_file
