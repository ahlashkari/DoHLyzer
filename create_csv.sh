#!/bin/bash

for f in $(find /home/Mohammad/Workspace/DOH/data_collector/dumps/ -name '*.pcap');
do
    n="${f##*/}"
    ./dohlyzer.py -f "$f" -c "./new_layer2/${n%.pcap}.csv"
done
