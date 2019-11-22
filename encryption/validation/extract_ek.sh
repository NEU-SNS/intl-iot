#!/bin/bash

if [ $# != 2 ]
then
    echo "Usage: $0 pcapfile jsonfile"
    exit 0
fi

infile=$1
jsonfile=$2

echo "Tshark ek ${infile} ..."
tshark -r ${infile} -T ek -x > ${jsonfile}

echo "Done -> ${jsonfile}"