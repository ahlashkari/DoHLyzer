#!/bin/bash

in_path=$1
out_path=$2

for f in $(find "$in_path" -name '*.pcap');
do
    echo "./dohlyzer.py -f \"$f\" -s $out_path"
done
