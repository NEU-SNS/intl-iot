#!/bin/bash

usage() {
    echo -e "Usage: $0 in_pcap out_csv ek_json\n"
    echo -e "Performs encryption analysis. Decodes raw network data from a pcap file into a JSON file. Uses the JSON file to output a CSV file that includes the entropy of each packet and its classification (encrypted, text, media, unknown).\n"
    echo -e "Example: $0 samples/traffic.pcap output/traffic.csv output/traffic.json\n"
    echo "Arguments:"
    echo "  in_pcap: Path to the input pcap file"
    echo "  out_csv: Path to the output CSV file"
    echo "  ek_json: Path to the intermediate output JSON file"
    exit 0
}

check_args() {
    if [ $num_args != 3 ]
    then
        echo -e "\e[31mError: 3 arguments required. $num_args arguments found.\e[39m"
        usage
    fi

    errors=False
    if [[ $in_pcap != *.pcap ]]
    then
        errors=True
        echo -e "\e[31mError: $in_pcap is not a pcap file.\e[39m"
    elif ! [ -e $in_pcap ]
    then
        errors=True
        echo -e "\e[31mError: The input pcap file $in_pcap does not exist.\e[39m"
    fi
    if [[ $out_csv != *.csv ]]
    then
        errors=True
        echo -e "\e[31mError: The output file $out_csv is not a CSV file.\e[39m"
    fi
    if [[ $ek_json != *.json ]]
    then
        errors=True
        echo -e "\e[31mError: The intermediate output file $ek_json is not a json file.\e[39m"
    fi

    if [ $errors == True ]
    then
        usage
    fi
}

run_pipeline() {
    dir="$(dirname $ek_json)"
    if ! [ -d $dir ]
    then
        mkdir -pv $dir
    fi

    echo "Running tshark -r $in_pcap -T ek -x > $ek_json"
    echo " ... waiting for the return code to be 0."

    tshark -r $in_pcap -T ek -x > $ek_json

    echo -e "Return code: $?\n"

    echo "Running python shrink_compute.py $ek_json $out_csv"
    echo " ... waiting for the return code to be 0."

    python shrink_compute.py $ek_json $out_csv

    echo -e "Return code: $?\n"

    echo "The result file should be at $out_csv"
}

echo "Performing encryption analysis..."
echo "Running encryption.sh..."

num_args=$#
in_pcap=$1
out_csv=$2
ek_json=$3

check_args
run_pipeline

