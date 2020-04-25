#!/bin/bash

usage() {
    exit_stat=$1
    usg_stm="
Usage: $path [OPTION]...

Predicts the device activity of a pcap file using a machine learning model
that is created using several input pcap files with known device activity.
To create the models, the input pcap files are decoded into human-readable
text files. Statistical analysis is performed on this data, which can then
be used to generate the machine learning models. There currently are three
algorithms available to generate the models.

Example: $path -i exp_list.txt -rn -d yi-camera -l knn -p yi_camera_sample.pcap -o sample.csv

Options:
  -i EXP_LIST_PATH path to text file containing filepaths to the pcap files used
                     to generate machine learning models (Default = exp_list.txt)
  -t IMD_DIR       path to the directory to place the decoded pcap files
                     (Default = tagged-intermediate/us/)
  -f FEATURES_DIR  path to the directory to place the statistically-analyzed files
                     (Default = features/us/)
  -m MODEL_DIR     path to the directory to place the generated models
                     (Default = tagged-models/us/)
  -k               generate a model using the kmeans algorithm
  -n               generate a model using the knn algorithm
  -r               generate a model using the rf algorithm
  -p PCAP_PATH     path to the pcap file with unknown device activity
                     (Default = yi_camera_sample.pcap)
  -d DEVICE_NAME   name of the device that generated the data in PCAP_PATH
                     (Default = yi-camera)
  -l MODEL_NAME    name of the model to be used to the device activity in
                     PCAP_PATH; choose from kmeans, knn, or rf (Default = rf)
  -o RESULT_PATH   path to a CSV file to write the results of predicting the
                     device activity of PCAP_PATH (Default = sample.csv)
  -h               display this help message

Notes: 
 - All directories and RESULT_PATH will be generated if they currently do not exist.
 - If no model is specified to be generated, all five models will be generated.

For more information, see model_details.md."

    if [ $exit_stat -eq 0 ]
    then
        echo -e "$usg_stm"
    else
        echo -e "$usg_stm" >&2
    fi
    exit $exit_stat
}

read_args() {
    while getopts "i:t:f:m:knrp:d:l:o:h" opt
    do
        case $opt in
            i)
                exp_list="$OPTARG"
                ;;
            t)
                intermediate_dir="$OPTARG"
                ;;
            f)
                features_dir="$OPTARG"
                ;;
            m)
                models_dir="$OPTARG"
                ;;
            k|n|r)
                model_gen="${model_gen}${opt}"
                ;;
            p)
                pcap_path="$OPTARG"
                ;;
            d)
                device_name="$OPTARG"
                ;;
            l)
                model_name="$OPTARG"
                ;;
            o)
                result_path="$OPTARG"
                ;;
            h)
                usage 0
                ;;
            *)
                usage 1
                ;;
        esac
    done

    if [[ $model_gen == "" ]]
    then
        model_gen="dknrs"
    fi
}

check_args_files() {
    echo -e "Checking files and arguments...\n"

    errors=false

    #Check raw2intermediate script exists and has proper permissions
    if ! [ -f $raw2int ]
    then
        errors=true
        echo -e "${red}${path}: Error: The script \"$raw2int\" cannot be found." >&2
        echo -e "${red}       Please make sure it is in the same directory as \"${path}\".$end" >&2
    else
        if ! [ -r $raw2int ]
        then
            errors=true
            echo -e "${red}${path}: Error: The script \"$raw2int\" does not have read permission.$end" >&2
        fi
        if ! [ -x $raw2int ]
        then
            errors=true
            echo -e "${red}${path}: Error: The script \"$raw2int\" does not have execute permission.$end" >&2
        fi
    fi
    
    #Check that rest of the scripts exists and have proper permissions
    files=($ext_features $train_models $predict)
    for f in ${files[@]}
    do
        if ! [ -f $f ]
        then
            errors=true
            echo -e "${red}${path}: Error: The script \"$f\" cannot be found." >&2
            echo -e "${red}       Please make sure it is in the same directory as \"${path}\".$end" >&2
        elif ! [ -r $f ]
        then
            errors=true
            echo -e "${red}${path}: Error: The script \"$f\" does not have read permission.$end" >&2
        fi
    done
    
    #Check that experiment list is a text file and exists
    if [[ $exp_list != *.txt ]]
    then
        errors=true
        echo -e "${red}${path}: Error: \"$exp_list\" is not a text (.txt) file.$end" >&2
    elif ! [ -e $exp_list ]
    then
        errors=true
        echo -e "${red}${path}: Error: The text file \"$exp_list\" does not exist.$end" >&2
    fi

    #Check that model name used for prediction is valid
    case $model_name in
        kmeans | knn | rf)
            ;;
        *)
            errors=true
            echo -e "${red}${path}: Error: \"${model_name}\" is an invalid model name.$end" >&2
            ;;
    esac

    #Check that the unknown-activity pcap file is a pcap file and exists
    if [[ $pcap_path != *.pcap ]]
    then
        errors=true
        echo -e "${red}${path}: Error: \"$pcap_path\" is not a pcap file.$end" >&2
    elif ! [ -e $pcap_path ]
    then
        errors=true
        echo -e "${red}${path}: Error: The input pcap file \"$pcap_path\" does not exist.$end" >&2
    fi

    #Check that the result file is a CSV file
    if [[ $result_path != *.csv ]]
    then
        errors=true
        echo -e "${red}${path}: Error: The result file \"$result_path\" should have a .csv extension.$end" >&2
    fi

    if [[ $errors == true ]]
    then
        usage 1
    fi
}

check_ret_code() {
    ret_code=$1
    file=$2
    if [ $ret_code -ne 0 ]
    then
        echo -e "${red}${path}: Error: Something went wrong with \"$(basename $file)\". Exit status $ret_code.$end" >&2
        echo -e "${red}       Please make sure you have properly set up your environment.$end" >&2
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
    python $train_models -f $features_dir -m $models_dir -$model_gen
    check_ret_code $? $train_models

    echo -e "\nStep 4: Predicting device activity..."
    python -W ignore $predict $device_name $model_name $pcap_path $result_path $models_dir
    check_ret_code $? $predict
}

echo "Performing content analysis pipeline..."
echo "Running $0..."

begin=`date '+%A %d %B %Y %T %Z %s'`
echo "Start time: $(echo $begin | cut -d ' ' -f -6)"
begin_time=$(echo $begin | cut -d ' ' -f 7-)

red="\e[31;1m"
end="\e[0m"
path=$0
model_dir=$(dirname $path)
raw2int="${model_dir}/raw2intermediate.sh"
ext_features="${model_dir}/extract_tbp_features.py"
train_models="${model_dir}/eval_models_all.py"
predict="${model_dir}/predict.py"

exp_list="${model_dir}/exp_list.txt"
intermediate_dir="${model_dir}/tagged-intermediate/us"
features_dir="${model_dir}/features/us"
models_dir="${model_dir}/tagged-models/us"
model_gen=""
device_name="yi-camera"
model_name="rf"
pcap_path="${model_dir}/yi_camera_sample.pcap"
result_path="${model_dir}/sample.csv"

read_args $@
check_args_files
#run_pipeline

finish=`date '+%A %d %B %Y %T %Z %s'`
echo "End time: $(echo $finish | cut -d ' ' -f -6)"
finish_time=$(echo $finish | cut -d ' ' -f 7-)

#Calculate elapsed time
sec=$(($finish_time-$begin_time))
hrs=$(($sec/3600))
if [ $hrs -ne 0 ]
then
    sec=$(($sec-($hrs*3600)))
fi
min=$(($sec/60))
if [ $min -ne 0 ]
then
    sec=$(($sec-($min*60)))
fi

echo "Time elapsed: $hrs hours $min minutes $sec seconds"

echo -e "\nContent analysis finished."
