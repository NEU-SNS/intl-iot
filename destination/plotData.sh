#!/bin/bash

expDir=$1
country=$2
output=${3:-"experiment_${country}.csv"}
lab=${4:-"icl"}
network=${5:-"icl"}

for f in $(find $expDir -name "*.pcap" | grep -v companion | grep "2019-05-08_"); do
	device=$(echo $f | sed 's,'"$expDir"'/\([^\/]\+\).*,\1,g')
	experiment=$(echo $f | sed 's,'"$expDir"'/\([^\/]\+\)/\([^\/]\+\).*,\2,g')
	#mac=$(grep " $device\$" aux/devices_${country}.txt | gawk '{print $1}')
  deviceList="aux/devices_${country}.txt"

	echo python analyze.py -i $f -s aux/tshark_all.hosts -d $device -c $deviceList -e $experiment -b $lab -n $network -o $output
	python analyze.py -i $f -s aux/tshark_all.hosts -d $device -c $deviceList -e $experiment -b $lab -n $network -o $output
done;
