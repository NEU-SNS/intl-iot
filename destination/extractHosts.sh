#!/bin/bash

dirName=$1
fileName=${2:-"tshark.hosts"}

for f in $(find $dirName -name "*.pcap"); do tshark -r $f -q -z hosts | awk 'NF && $1!~/^#/' >> ${fileName}_tmp; done;

sort ${fileName}_tmp | uniq > $fileName

rm ${fileName}_tmp
