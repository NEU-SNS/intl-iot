#!/bin/bash

if [ $# != 1 ]
then
	echo "Usage: $0 raw_list"
	echo "  raw_list: Text file containing a list of the paths to pcap files to analyze"
	exit 0
fi

raw_file_list=$1

./raw2intermediate.sh ${raw_file_list}

python extract_tbp_features.py

python train_rf_models.py

./predict.sh yi-camera sample-yi-camera-recording.pcap sample-result.csv tagged-models/us/
