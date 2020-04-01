#!/bin/bash

dataDir=$1

for f in $(find $dataDir -name "*.pcap"); do

  tshark -r $f -T fields -e ip.src -e ip.dst | gawk '{print $1"\n"$2}' | sort | uniq >> aux/ipList

done

