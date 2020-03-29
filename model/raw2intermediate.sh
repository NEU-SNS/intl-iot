#!/bin/bash

usage() {
    echo -e "Usage: $0 exp_list out_intermediate_dir\n"
    echo -e "Decodes raw data in pcap files into human-readable text files.\n"
    echo -e "Example: $0 list_exp.txt tagged-intermediate/us/\n"
    echo "Arguments:"
    echo "  exp_list: A text file containing the file paths to pcap files to decode"
    echo "  out_intermediate_dir: Path to the directory to place the human-readable raw decoded output text files"

#    echo "       e.g. $0 aux/list_tagged.txt /net/data/meddle/moniotr/tagged-intermediate"
#    echo "       // e.g. find traffic/us/ -name *.pcap > list_exp.txt"
#    echo "       Example in tagged-examples.txt"
    exit 0
}

echo -e "\nTranslating raw pcaps into human-readable form..."
echo "Running $0..."

red="\e[31;1m"
end="\e[0m"

#Check for 2 arguments
if [ $# -ne 2 ]
then
    echo -e "${red}Error: 2 arguments required. $# arguments found.$end"
    usage
fi

inputFile=$1
dirIntermediate=$2

#Check that exp_list is a .txt file and exists
if [[ $inputFile != *.txt ]]
then
    echo -e "${red}Error: Input file must be a text file (.txt). Received $1.$end"
    usage
elif ! [ -e $inputFile ]
then
    echo -e "${red}Error: The input file $inputFile does not exist.$end"
fi

extract_pcap() {
    pcap_file=$1
    txt_file=$2

    #If output file exists, nothing happens
    if [ -e ${txt_file} ]
    then
        echo "${txt_file} exists, delete it to re-parse!"
        return
    fi

    #Decode pcap file
    tshark -r ${pcap_file} -Y ip -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta -e frame.protocols -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e ssl.handshake.extensions_server_name -e udp.srcport -e udp.dstport -E separator=/t > ${txt_file} 2>/dev/null

    #Check if tshark worked
    if ! [ -s ${txt_file} ]
    then
        echo "Empty file ${txt_file}, removing..."
        rm -v ${txt_file}
	echo
    else
        head -3 ${txt_file}
        wc -l ${txt_file}
        echo
    fi
}

while read line
do
    #Check that files in input file exist and are .pcap files
    if ! [ -e $line ]
    then
        echo -e "${red}The file $line does not exist!$end\n"
    elif ! [[ $line == *.pcap ]]
    then
        echo -e "${red}The file $line is not a .pcap file!$end\n"
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
