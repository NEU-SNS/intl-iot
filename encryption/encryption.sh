#!/bin/bash

if [ $# != 3 ]
then
	echo "Usage: $0 in_file out_file ek_file"
	echo "  in_file: path to input pcap file"
	echo "  out_file: path to csv file that output will write to"
	echo "  ek_file: path to json file to hold intermediate results"
	exit 0
fi

in_file=$1 #samples/traffic.pcap
out_file=$2 #output/traffic.csv
ek_file=$3 #output/traffic.json

echo "Running tshark -r $in_file -T ek -x > $ek_file"
echo " ... waiting for the return code to be 0."

tshark -r $in_file -T ek -x > $ek_file

echo -e "Return code: $?\n"

echo "Running python shrink_compute.py $ek_file $out_file"
echo " ... waiting for the return code to be 0."

python shrink_compute.py $ek_file $out_file

echo -e "Return code: $?\n"

echo "The result file should be at $out_file"
