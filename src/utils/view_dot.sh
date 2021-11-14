#!/bin/bash
# set -x
set -u
set -e

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <file.dot> <tainted_list.txt>"
    exit 1
fi

dot_file=$1
tainted_list=$2
output_file="${dot_file/.dot/}.tainted.dot"
echo "Writing $output_file"

cp $dot_file $output_file
# create a big OR of all the function names to make sed parse them efficiently
echo -n 's/(' > /tmp/sedscript
while read line; do
  echo "tainting: $line"
  echo -n "label=\"\{$line\}\"|" >> /tmp/sedscript
done <$tainted_list
# random strig to close parentesis with no | at the end, still dev sloppiness
echo '44b573951b45800b992db88eb5e460d2)/\1 ,style=filled, fillcolor=\"green\"/' >> /tmp/sedscript
echo "Executing sed script"
sed -i -E -f /tmp/sedscript $output_file

echo "Removing DFL helpers"
# remove DFL functions
for node in `grep 'dfl' $output_file | sed 's/\t//' | cut -d' ' -f 1`; do
    sed -i "/$node/d" $output_file
done

echo "Removing CFL helpers"
# remove CFL functions
for node in `grep '{cfl' $output_file | sed 's/\t//' | cut -d' ' -f 1`; do
    sed -i "/$node/d" $output_file
done

xdot $output_file
