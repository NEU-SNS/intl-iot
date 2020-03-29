#!/bin/bash

usage() {
	echo -e "Usage: $0 exp_list intermediate_dir features_dir model_dir device_name pcap_path result_path\n"
    echo "Performs the content analysis pipeline. Converts raw network data into human-readable"
    echo "but still raw data. Performs statistical analysis on raw data to create a model,"
    echo "which can be used to predict the amount of device activity that can be inferred"
    echo -e "based on the network data of that device.\n"
    echo -e "Example: $0 list_exp.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera yi_camera_sample.pcap sample.csv\n"
    echo "Arugments:"
	echo "  exp_list: Text file containing filepaths to pcap files to analyze"
    echo "  intermediate_dir: Path to the directory to place the decoded pcap files"
    echo "  features_dir: Path to the directory to place the analyzed files"
    echo "  model_dir: Path to the directory to place the generated models"
    echo "  device_name: Name of the device that generated the data in the pcap file that will"
    echo "               be used to predict device activity"
    echo "  pcap_path: Path to the pcap file with unknown device activity"
    echo "  result_path: Path to a CSV file to write the results"
	exit 0
}

check_args_files() {
    echo -e "Checking files and arguments...\n"

    errors=false

    #Check raw2intermediate script exists and has proper permissions
    if ! [ -f $raw2int ]
    then
        errors=true
        echo -e "${red}Error: The script \"$raw2int\" cannot be found."
        echo -e "${red}       Please make sure it is in the same directory as \"${path}\".$end"
    else
        if ! [ -r $raw2int ]
        then
            errors=true
            echo -e "${red}Error: The script \"$raw2int\" does not have read permission.$end"
        fi
        if ! [ -x $raw2int ]
        then
            errors=true
            echo -e "${red}Error: The script \"$raw2int\" does not have execute permission.$end"
        fi
    fi
    
    #Check that rest of the scripts exists and have proper permissions
    for f in ${files[@]}
    do
        if ! [ -f $f ]
        then
            errors=true
            echo -e "${red}Error: The script \"$f\" cannot be found."
            echo -e "${red}       Please make sure it is in the same directory as \"${path}\".$end"
        elif ! [ -r $f ]
        then
            errors=true
            echo -e "${red}Error: The script \"$f\" does not have read permission.$end"
        fi
    done
    
    #Check that seven arguments are provided
    if [ $num_args -ne 7 ]
    then
        echo -e "${red}Error: 7 aruments required. $num_args arguments found.$end"
        usage
    fi

    #Check that experiment list is a text file and exists
    if [[ $exp_list != *.txt ]]
    then
        errors=true
        echo -e "${red}Error: $exp_list is not a text (.txt) file.$end"
    elif ! [ -e $exp_list ]
    then
        errors=true
        echo -e "${red}Error: The pcap file $exp_list does not exist.$end"
    fi

    #Check that the unknown-activity pcap file is a pcap file and exists
    if [[ $pcap_path != *.pcap ]]
    then
        errors=true
        echo -e "${red}Error: $pcap_path is not a pcap file.$end"
    elif ! [ -e $pcap_path ]
    then
        errors=true
        echo -e "${red}Error: The input pcap file $pcap_path does not exist.$end"
    fi

    #Check that the result file is a CSV file
    if [[ $result_path != *.csv ]]
    then
        errors=true
        echo -e "${red}Error: The result file $result_path should have a .csv extension.$end"
    fi

    if [[ $errors == true ]]
    then
        usage
    fi
}

check_ret_code() {
    ret_code=$1
    file=$2
    if [ $ret_code -ne 0 ]
    then
        echo -e "${red}Error: Something went wrong with $(basename $file). Exit status $ret_code.$end"
        echo -e "${red}       Please make sure you have properly set up your environment.$end"
        exit $ret_code
    fi
}

run_pipeline() {
    echo -e "\nStep 1: Decoding raw pcaps into human-readable form..."
    $raw2int $exp_list $intermediate_dir
    check_ret_code $? $raw2int

    echo -e "\nStep 2: Performing statistical analysis..."
    python $ext_features $intermediate_dir $features_dir
    check_ret_code $? $ext_features

    echo -e "\nStep 3: Training data and creating model..."
    python $train_models $features_dir $model_dir
    check_ret_code $? $train_models

    echo -e "\nStep 4: Predicting device activity..."
    python -W ignore $predict $device_name $pcap_path $result_path $model_dir
    check_ret_code $? $predict
}

echo "Performing content analysis pipeline..."
echo "Running $0..."

red="\e[31;1m"
end="\e[0m"
num_args=$#
path=$0
model_dir=$(dirname $path)
raw2int="${model_dir}/raw2intermediate.sh"
ext_features="${model_dir}/extract_tbp_features.py"
train_models="${model_dir}/train_rf_models.py"
predict="${model_dir}/predict.py"

files=($ext_features $train_models $predict)

exp_list=$1
intermediate_dir=$2
features_dir=$3
model_dir=$4
device_name=$5
pcap_path=$6
result_path=$7

check_args_files
run_pipeline

echo -e "\nContent analysis finished."
