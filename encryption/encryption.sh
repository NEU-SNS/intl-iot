#!/bin/bash

print_usage() {
    exit_stat=$1
    usg_stm="
Usage: $0 in_pcap out_csv ek_json

Performs encryption analysis. Decodes raw network data from a pcap file into an
intermediate JSON. Uses the JSON file to output a CSV file that includes the
entropy of each packet and its classification (encrypted, text, media, unknown).

Example: $0 sample.pcap sample.csv sample.json

Arguments:
  in_pcap: path to the input pcap file
  out_csv: path to the output CSV file
  ek_json: path to the intermediate JSON file

Note:
 - If out_csv or ek_json does not current exist, the files will be generated.
     If the files currently exist, they will be overwritten.

For more information, see the README."

    if [ $exit_stat -eq 0 ]
    then
        echo -e "$usg_stm"
    else
        echo -e "$usg_stm" >&2
    fi
    exit $exit_stat
}


check_args_files() {
    for arg in "$@"
    do
        if [ "$arg" == "-h" ] || [ "$arg" == "--help" ]
        then
            print_usage 0
        fi
    done

    errors=false

    #Test that TShark is installed properly
    tshark -h > /dev/null
    if [ $? -ne 0 ]
    then
        errors=true
        echo -e "${red}${path}: Error: TShark does not seem to be properly installed.$end" >&2
    fi
    
    #Check that the computation file exists and has proper permissions
    if ! [ -f $shrink_comp ]
    then
        errors=true
        echo -e "${red}${path}: Error: The script \"$shrink_comp\" cannot be found.$end" >&2
        echo -e "${red}    Please make sure it is in the same directory as ${path}.$end" >&2
    elif ! [ -r $shrink_comp ]
    then
        errors=true
        echo -e "${red}${path}: Error: The script \"$shrink_comp\" does not have read permission.$end" >&2
    fi

    #Check that three arguments are passed in
    if [ $num_args -ne 3 ]
    then
        echo -e "${red}${path}: Error: 3 arguments required. $num_args arguments found.$end" >&2
        print_usage 1
    fi

    in_pcap=$1
    out_csv=$2
    ek_json=$3

    #Check that the input pcap file is a pcap file and exists
    if [[ $in_pcap != *.pcap ]]
    then
        errors=true
        echo -e "${red}${path}: Error: $in_pcap is not a pcap file.$end" >&2
    elif ! [ -e $in_pcap ]
    then
        errors=true
        echo -e "${red}${path}: Error: The input pcap file $in_pcap does not exist.$end" >&2
    fi

    #Check that the output CSV file is a CSV file
    if [[ $out_csv != *.csv ]]
    then
        errors=true
        echo -e "${red}${path}: Error: The output file $out_csv is not a CSV file.$end" >&2
    fi

    #Check that the intermediate JSON file is a JSON file
    if [[ $ek_json != *.json ]]
    then
        errors=true
        echo -e "${red}${path}: Error: The intermediate output file $ek_json is not a JSON file.$end" >&2
    fi

    if [[ $errors == true ]]
    then
        print_usage 1
    fi
}

check_ret_code() {
    ret_code=$1
    file=$2
    if [ $ret_code -ne 0 ]
    then
        echo -e "${red}${path}: Error: Something went wrong with \"$(basename $file)\". Exit status $ret_code.$end" >&2
        echo -e "${red}    Please make sure you have properly set up your environment.$end" >&2
        exit $ret_code
    fi
}

run_pipeline() {
    dir="$(dirname $ek_json)"
    if ! [ -d $dir ]
    then
        mkdir -pv $dir
    fi

    echo -e "\nRunning \"tshark -r $in_pcap -T ek -x > $ek_json\"..."
    tshark -r $in_pcap -T ek -x > $ek_json
    check_ret_code $? "TShark"

    echo -e "\nRunning \"python3 $shrink_comp $ek_json $out_csv\"..."
    python3 -W ignore $shrink_comp $ek_json $out_csv
    check_ret_code $? $shrink_comp
}

### Begin Encryption Analysis ###

red="\e[31;1m"
end="\e[0m"
num_args=$#
path=$0
enc_dir=$(dirname $path)
shrink_comp="${enc_dir}/shrink_compute.py"

in_pcap=""
out_csv=""
ek_json=""

check_args_files $@

echo "Performing encryption analysis..."
echo "Running $(basename $0)..."

run_pipeline

echo -e "\nEncryption analysis finished."

