#!/bin/bash

if [ $# != 1 ]
then
    echo "Usage: $0 list_exp.txt"
#    echo "       e.g. $0 aux/list_tagged.txt /net/data/meddle/moniotr/tagged-intermediate"
#    echo "       // e.g. find traffic/us/ -name *.pcap > list_exp.txt"
#    echo "       Example in tagged-examples.txt"
    exit 0
fi

inputFile=$1
dirIntermediate="tagged-intermediate/us"


extract_pcap(){
    pcap_file=$1
    txt_file=$2

    if [ -e ${txt_file} ]
    then
        echo "${txt_file} exists, delete it to re-parse!"
        return
    fi

    tshark -r ${pcap_file} -Y ip -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta -e frame.protocols -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e ssl.handshake.extensions_server_name -e udp.srcport -e udp.dstport -E separator=/t > ${txt_file} 2>/dev/null


    if ! [ -s ${txt_file} ]
    then
        echo "Empty file ${txt_file}, removing..."
        rm -v ${txt_file}
    else
        head -3 ${txt_file}
        wc -l ${txt_file}
        echo
    fi

}

while read line
do
    echo $line
    dname=`dirname $line`
    fname=`basename $line`
    fname=${fname%pcap}txt
    expName=`basename $dname`
    devicedir=`dirname $dname`
    deviceName=`basename $devicedir`

    dirTarget=${dirIntermediate}/${deviceName}/${expName}
    mkdir -p $dirTarget

    fileIntermediate=${dirTarget}/$fname
    if ! [ -e $fileIntermediate ]
    then
        echo "extract_pcap $line $fileIntermediate"
        extract_pcap $line $fileIntermediate
    else
        echo  "$fileIntermediate exists."
    fi
done < $inputFile
