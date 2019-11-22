#!/bin/bash
DIR_TXT=synthetic

for f in ${DIR_TXT}/*.pcap
do
    jf=${f%.pcap}.json
    if ! [ -e $jf ]
    then
        ./extract_ek.sh $f $jf
    fi

    cf=${f%pcap}csv
    if ! [ -e $cf ]
    then
        python filter_compute.py $jf . $cf
    fi
done