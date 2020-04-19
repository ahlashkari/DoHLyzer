#!/bin/bash

in_path=$1
out_path=$2

for f in $(find "$in_path" -name '*.pcap');
do
    n="${f##*/}"
    rand=`openssl rand -hex 3`
    echo "./dohlyzer.py -f \"$f\" -c \"$out_path/${n%.pcap}.$rand.csv\""
done
