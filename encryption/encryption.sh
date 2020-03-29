#!/bin/bash

usage() {
    echo -e "Usage: $0 in_pcap out_csv ek_json\n"
    echo "Performs encryption analysis. Decodes raw network data from a pcap file into a"
    echo "JSON file. Uses the JSON file to output a CSV file that includes the entropy of"
    echo -e "each packet and its classification (encrypted, text, media, unknown).\n"
    echo -e "Example: $0 sample.pcap sample.csv sample.json\n"
    echo "Arguments:"
    echo "  in_pcap: Path to the input pcap file"
    echo "  out_csv: Path to the output CSV file"
    echo "  ek_json: Path to the intermediate JSON file"
    exit 0
}

check_args_files() {
    echo -e "Checking files and arguments...\n"

    errors=false

    #Check that the computation file exists and has proper permissions
    if ! [ -f $shrink_comp ]
    then
        errors=true
        echo -e "${red}Error: The script \"$shrink_comp\" cannot be found.$end"
        echo -e "${red}       Please make sure it is in the same directory as ${path}.$end"
    elif ! [ -r $shrink_comp ]
    then
        errors=true
        echo -e "${red}Error: The script \"$shrink_comp\" does not have read permission.$end"
    fi

    #Check that three arguments are passed in
    if [ $num_args -ne 3 ]
    then
        echo -e "${red}Error: 3 arguments required. $num_args arguments found.$end"
        usage
    fi

    #Check that the input pcap file is a pcap file and exists
    if [[ $in_pcap != *.pcap ]]
    then
        errors=true
        echo -e "${red}Error: $in_pcap is not a pcap file.$end"
    elif ! [ -e $in_pcap ]
    then
        errors=true
        echo -e "${red}Error: The input pcap file $in_pcap does not exist.$end"
    fi

    #Check that the output CSV file is a CSV file
    if [[ $out_csv != *.csv ]]
    then
        errors=true
        echo -e "${red}Error: The output file $out_csv is not a CSV file.$end"
    fi

    #Check that the intermediate JSON file is a JSON file
    if [[ $ek_json != *.json ]]
    then
        errors=true
        echo -e "${red}Error: The intermediate output file $ek_json is not a JSON file.$end"
    fi

    if [[ $errors == true ]]
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

    return_code=$?
    echo -e "Return code: $return_code\n"

    if [ $return_code -ne 0 ]
    then
        echo -e "${red}Error: Something went wrong with TShark."
        echo -e "${red}       Please make sure you have set up a proper environment.$end"
        exit $return_code
    fi

    echo "Running python $shrink_comp $ek_json $out_csv"
    echo " ... waiting for the return code to be 0."

    python $shrink_comp $ek_json $out_csv

    return_code=$?
    echo -e "Return code: $return_code\n"
    if [ $return_code -ne 0 ]
    then
        echo -e "${red}Error: Something went wrong with $(basename $shrink_comp)."
        echo -e "${red}       Please make sure you have properly set up your environment.$end"
        exit $return_code
    fi

    echo "The result file should be at $out_csv"
}

echo "Performing encryption analysis..."
echo "Running $(basename $0)..."

red="\e[31;1m"
end="\e[0m"
num_args=$#
path=$0
enc_dir=$(dirname $path)
shrink_comp="${enc_dir}/shrink_compute.py"

in_pcap=$1
out_csv=$2
ek_json=$3

check_args_files
run_pipeline

echo -e "\nEncryption analysis finished."
