#!/bin/bash

usage() {
    usg_stm="
Usage: $0 exp_list out_imd_dir

Decodes raw pcap data into human-readable text files.

Example: $0 exp_list.txt tagged-intermediate/us/

Arguments:
  exp_list:    a text file containing the file paths to pcap files to decode
  out_imd_dir: path to the directory to place the output human-readable decoded output;
                 directory will be generated if it does not already exist
                 
For more information, see model_details.md."

    echo -e "$usg_stm" >&2
    exit 1
}

extract_pcap() {
    pcap_file=$1
    txt_file=$2

    #Decode pcap file
    tshark -r ${pcap_file} -Y ip -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta -e frame.protocols -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e udp.srcport -e udp.dstport -E separator=/t > ${txt_file} 2>/dev/null

    #Check if tshark worked
    if ! [ -s ${txt_file} ]
    then
        echo "Empty file ${txt_file}, removing..."
        rm -v ${txt_file}
	echo
    else
        head -3 ${txt_file}
        echo "Line count: $(wc -l ${txt_file})"
        echo
    fi
}

echo "Running $0..."

red="\e[31;1m"
end="\e[0m"

#Check for 2 arguments
if [ $# -ne 2 ]
then
    echo -e "${red}$0: Error: 2 arguments required. $# arguments found.$end" >&2
    usage
fi

inputFile=$1
dirIntermediate=$2

#Check that exp_list is a .txt file and exists
if [[ $inputFile != *.txt ]]
then
    echo -e "${red}$0: Error: Input file must be a text file (.txt). Received $1.$end" >&2
    usage
elif ! [ -e $inputFile ]
then
    echo -e "${red}$0: Error: The input file $inputFile does not exist.$end" >&2
    usage
fi

echo "Input files located in: $inputFile"
echo "Output files placed in: $dirIntermediate"

while read line
do
    #Check that files in input file exist and are .pcap files
    if ! [ -e $line ]
    then
        echo -e "${red}$0: The file $line does not exist!$end\n" >&2
    elif ! [[ $line == *.pcap ]]
    then
        echo -e "${red}$0: The file $line is not a .pcap file!$end\n" >&2
    else
     
    #Parse pcap file name
    dname=`dirname $line`
    fname=`basename $line`
    fname=${fname%pcap}txt
    expName=`basename $dname`
    devicedir=`dirname $dname`
    deviceName=`basename $devicedir`

    dirTarget=${dirIntermediate}/${deviceName}/${expName}
    mkdir -p $dirTarget

    fileIntermediate=${dirTarget}/$fname #output files
    #Nothing happens if output file exists
    if ! [ -e $fileIntermediate ]
    then
        echo "Decoding $line into $fileIntermediate"
        extract_pcap $line $fileIntermediate
    else
        echo "$fileIntermediate exists."
    fi
fi
done < $inputFile
