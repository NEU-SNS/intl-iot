#!/bin/bash

if [ $# != 4 ]
then
    echo "Usage: $0 device_name path-to-pcap result-file modeldir"
#    echo "Test: $0 blink-camera examples/blink-camera/local_move/2018-12-11_18:09:43.76s.pcap res.txt/csv"
#    echo "Test: $0 blink-camera /home/renjj/moniotr/tagged/blink-camera/local_move/2018-12-11_18:09:43.76s.pcap res.txt/csv"
    echo "    Note that a temprary file  /tmp/{md5}.txt will be created during the process"
    echo "    Requires python3"
    exit 0
fi

deviceName=$1
pcapFile=$2
resFile=$3
dirmodels=$4
if [ "`uname`" = "Linux" ]
then
    m5=`echo "$1$2" | md5sum | awk '{print $1}'`
else
    m5=`echo "$1$2" | md5`
fi
# -`date +%s`
tmpFile=/tmp/${m5}.txt
echo $tmpFile
# pcap => features
if [ -e ${tmpFile} ]
then
    echo "${tmpFile} exists, delete it to re-parse!"
else
    tshark -r ${pcapFile} -Y ip -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta -e frame.protocols -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e ssl.handshake.extensions_server_name -e udp.srcport -e udp.dstport -E separator=/t > $tmpFile 2>/dev/null
fi
#echo "  python3  -W ignore predict.py ${deviceName} ${tmpFile} ${resFile} ${dirmodels}"
mkdir -p `dirname ${resFile}`
python3  -W ignore predict.py ${deviceName} ${tmpFile} ${resFile} ${dirmodels}
