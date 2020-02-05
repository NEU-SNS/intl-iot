#!/bin/bash

usage() {
    echo -e "Usage: $0 device_name pcap_path result_path model_dir\n"
    echo -e "Predicts the amount of device activity that can be inferred based on the network traffic of that device.\n"
    echo -e "Example: $0 yi-camera sample-yi-camera-recording.pcap sample-result.csv tagged-models/us/\n"
    echo "Arguments:"
    echo "  device_name: The name of the device that the pcap file contains network traffic of"
    echo "  pcap_path: Path to the network activity in a pcap file"
    echo "  result_path: Path to CSV file to write results"
    echo -e "  model_dir: Path to thee directory containing the model of the device that the pcap file samples\n"
#    echo "Test: $0 blink-camera examples/blink-camera/local_move/2018-12-11_18:09:43.76s.pcap res.txt/csv"
#    echo "Test: $0 blink-camera /home/renjj/moniotr/tagged/blink-camera/local_move/2018-12-11_18:09:43.76s.pcap res.txt/csv"
    echo "Note that a temprary file /tmp/{md5}.txt will be created during the process to hold data about the decoded pcap file."
    echo "Requires python3."
    exit 0
}

if [ $# != 4 ]
then
    echo -e "\e[31mError: 4 arguments required. $# arguments found.\e[39m"
    usage
fi

deviceName=$1
pcapFile=$2
resFile=$3
dirmodels=$4

errors=false #Allows more than one error to be detected
if [[ $pcapFile != *.pcap ]]
then
    errors=true
    echo -e "\e[31mError: $pcapFile is not a pcap file.\e[39m"
elif ! [ -e $pcapFile ]
then
    errors=true
    echo -e "\e[31mError: The pcap file $pcapFile does not exist.\e[39m"
fi
if [[ $resFile != *.csv ]]
then
    errors=true
    echo -e "\e[31mError: The output file name should be a CSV file. Received $resFile\e[39m"
fi
if ! [ -d $dirmodels ]
then
    errors=true
    echo -e "\e[31mError: The directory $dirmodels does not exist.\e[39m"
else 
    if ! [ -e ${dirmodels}/${deviceName}.model ]
    then
        errors=true
        echo -e "\e[31mError: The model file ${dirmodels}/${deviceName}.model cannot be found. Please regenerate file, check directory name, or check device name.\e[39m"
    fi
    if ! [ -e ${dirmodels}/${deviceName}.label.txt ]
    then
        errors=true
        echo -e "\e[31mError: The label file ${dirmodels}/${deviceName}.label.txt cannot be found. Please regenerate file, check directory name, or check device name.\e[39m"
    fi
fi

if $errors
then
    usage
fi

echo -e "\nPredicting amount of inferable device activity from pcap file..."

if [ "`uname`" = "Linux" ]
then
    m5=`echo "$1$2" | md5sum | awk '{print $1}'`
else
    m5=`echo "$1$2" | md5`
fi
# -`date +%s`
tmpFile=/tmp/${m5}.txt

# pcap => features
if [ -e ${tmpFile} ]
then
    echo "${tmpFile} exists, delete it to re-parse the pcap file!"
else
    echo "Decoding $pcapFile to $tmpFile"
    tshark -r ${pcapFile} -Y ip -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta -e frame.protocols -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e ssl.handshake.extensions_server_name -e udp.srcport -e udp.dstport -E separator=/t > $tmpFile 2>/dev/null
fi
#echo "  python3  -W ignore predict.py ${deviceName} ${tmpFile} ${resFile} ${dirmodels}"
mkdir -vp `dirname ${resFile}` #Make directories to put result file in
python3 -W ignore predict.py ${deviceName} ${tmpFile} ${resFile} ${dirmodels}
