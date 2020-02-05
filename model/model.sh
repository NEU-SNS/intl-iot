#!/bin/bash

usage() {
	echo -e "Usage: $0 exp_list intermediate_dir features_dir model_dir device_name pcap_path result_path\n"
    echo -e "Performs the content analysis pipeline. Converts raw network data into human-readable but still raw data. Performs statistical analysis on raw data to create a model, which can be used to predict the amount of device activity that can be inferred based on the network data of that device.\n"
    echo -e "Example: $0 list_exp.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera sample-yi-camera-recording.pcap sample-result.csv\n"
    echo "Arugments:"
	echo "  exp_list: Text file containing filepaths to pcap files to analyze"
    echo "  intermediate_dir: Path to the directory to place the decoded pcap files"
    echo "  features_dir: Path to the directory to place the analyzed files"
    echo "  model_dir: Path to the directory to place the generated models"
    echo "  device_name: Name of the device that generated the data in the pcap file that will be used to predict the amount of device activity"
    echo "  pcap_path: Path to the pcap file that will be used to predict the amount of device activity"
    echo "  result_path: Path to a CSV file to write the results"
	exit 0
}

check_args() {
    if [ $num_args != 7 ]
    then
        echo -e "\e[31mError: 7 aruments required. $num_args arguments found.\e[39m"
        usage
    fi

    errors=False
    if [[ $exp_list != *.txt ]]
    then
        errors=True
        echo -e "\e[31mError: $exp_list is not a text (.txt) file.\e[39m"
    elif ! [ -e $exp_list ]
    then
        errors=True
        echo -e "\e[31mError: The pcap file $exp_list does not exist.\e[39m"
    fi
    if [[ $pcap_path != *.pcap ]]
    then
        errors=True
        echo -e "\e[31mError: $pcap_path is not a pcap file.\e[39m"
    elif ! [ -e $pcap_path ]
    then
        errors=True
        echo -e "\e[31mError: The input pcap file $pcap_path does not exist.\e[39m"
    fi
    if [[ $result_path != *.csv ]]
    then
        errors=True
        echo -e "\e[31m:Error: The result file $result_path should have a .csv extension.\e[39m"
    fi
}

run_pipeline() {
    echo "Running content analysis pipeline"

    ./raw2intermediate.sh $exp_list $intermediate_dir
    python extract_tbp_features.py $intermediate_dir $features_dir
    python train_rf_models.py $features_dir $model_dir
    ./predict.sh $device_name $pcap_path $result_path $model_dir

    echo -e "\nContent analysis finished."
}

num_args=$#
exp_list=$1
intermediate_dir=$2
features_dir=$3
model_dir=$4
device_name=$5
pcap_path=$6
result_path=$7

check_args
run_pipeline


