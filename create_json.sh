#!/bin/bash

for f in $(find /home/Mohammad/Dataset/LastVersion/Raw/Chrome/ -name '*.pcap');
do
    ./dohlyzer.py -f "$f" -s ./layer2/chrome/
done
