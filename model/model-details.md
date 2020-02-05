# Detailed Descriptions for Content Analysis Scripts
Below is a detailed description about the functions of each script run in [model_sample.ipynb](model_sample.ipynb).

## Scripts

### model.sh
Usage: ./model.sh exp_list intermediate_dir features_dir model_dir device_name pcap_path result_path
Example: ./model.sh list_exp.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera sample-yi-camera-recording.pcap sample-result.csv

This is the main script of the content analysis pipeline. The scripts listed below are parts of this pipeline. The main goal of this pipeline is to use machine learning to predict the amount of device activity that can be inferred given the network traffic of that device. First, the pipeline needs to create a model using machine learning. The raw network traffic (provided in pcap files) is translated into human-readable raw data. This raw data is then statistically analyzed and sent into an algorithm for training. Once trained, a model will be generated for each device. A pcap file with an unknown amount of device activity that can be inferred can be put through the same process of translating it into human-readable data and statistically analyzed. The analyzed data can then be used to predict the amount of device activity that can be inferred based on the network traffic.

Input:
  exp_list: The text file that contains paths to pcap files to analyze to generate the models.
  intermediate_dir: The path to the directory to place the decoded pcap files.
  features_dir: The path to the directory to place the analyzed files.
  model_dir: The path to the directory to place the generated models.
  device_name: The name of the device that generated the data in the pcap file that will be used to predict the amount of device activity.
  pcap_path: The path to the pcap file that will be used to predict the amount of device activity.
  result_path: The path to a CSV file to write the reslts.

Output:
This script produces a CSV file that contains the prediction of how much device activity can be inferred based on the device's network traffic. If the CSV exists, the script will overwrite it. Several intermediate files and directories are also produced, as described above.

### raw2intermediate.sh
Usage: ./raw2intermediate.sh exp_list out_intermediate_dir
Example: ./raw2intermediate list_exp.txt tagged-intermediate/us/

This script decodes data in pcap files listed in the input text file into human-readable text files using tshark.

Input:
  exp_list: A text file containing the filepaths to pcap files. Each filename should be on a newline in the text file.
  out_intermediate_dir: The path to the directory to place the decoded output text files.

Output:
A plaintext file will be produced for every pcap input file. Each output file contains a translation of the raw input file into human-readable form. The raw data output is tab-delimited and is in .txt format. If an output file already exists, tshark will not run the input file, and the existing output file will remain. If tshark cannot read the input file, no output file will be produced.

### extract_tbp_features.py
Usage: python extract_tbp_features.py in_intermediate_dir out_features_dir

This script takes the human-readable pcap data output from raw2intermediate.sh and performs data analysis on it.

Input:
  in_intermediate_dir: The path to a directory containing text files of human-readable raw pcap data.
  out_features_dir: The path to the directory to write the analyzed CSV files

Output:
Each valid input file (.txt) in the input directory will be analyzed, and an CSV file containing statistcal analysis will be produced in a cache/ directory in the specified output directory. After every input file is processed, all the CSV files of each device will be concatenated together in a separate CSV file, which will be placed in the specified output directory. If a device already has a concatenated CSV file, no analysis will occur for that device, and the existing file will remain. If a device does not have a concatenated CSV file, the program will regenerate any cache files, as necessary, and the cache files of the device will be concatenated. If an input file is not a text file (.txt.), no output will be produced for that file.

### train_rf_models.py
Usage: python train_rf_models.py in_features_dir out_model_dir

This script trains analyzed pcap data and generates a model that can predict device activity.

Input:
  in_features_dir: Path to a directory containing CSV files that have analyzed pcap data.
  out_model_dir: Path to the directory to place the generated model.

Output:
The script will generate three files for each device. One file contains the model, which can be used to predict device activity. A second file contains a list of experiment types. These two files are used in the next step of the pipeline. A third file contains the training accuracy scores for each device. If a device already has these three files in the output directory, they will not be regenerated. However, if one or more of those files are missing, they will be regenerated.

### predict.sh
Usage: ./predict.sh device_name pcap_path result_path model_dir

This script predicts the amount of device activity that can be inferred based on the network traffic of that device.

Input:
  device_name: The name of the device that the pcap file contains network traffic of.
  pcap_path: Path to the network activity in a pcap file.
  result_path: Path to a CSV file to write results.
  model_dir: The directory containing the model of the device that the pcap file samples.

Output:
The script checks that the input files and directories are valid. The script will then decode the input pcap file and store the data in a file called \tmp\{md5}.txt. If this file exists, a new file will not be generated. The script then calls predict.py to predict the amount of device activity that can be inferred given this decoded file.

### predict.py
Usage: python3 predict.py device_name intermediate_file result_file model_dir use_intermediate

The script uses a model to predict amount of device activity that can be inferred from a decoded pcap file. In the content analysis pipeline, this script is called by predict.sh, not by the user.

Input:
  device_name: The name of the device that the pcap file contains network traffic of.
  intermediate_path: Path to the decoded, human-readable pcap file.
  result_path: Path to a CSV file to write results.
  model_dir: The path to the directory containing the model of the device that the decoded pcap file samples.

Output:
The script outputs a CSV file containing the predictions made by the model. If the output file already exists, the script will overwrite the file.

## Non-scripts

### list_exp.txt
A list of pcap files containing network traffic data from several different devices.

### Model.md
A file which further explains the models.

### model_sample.ipynb
A Jupyter Notebook that contains runnable code with the same commands as model.sh. However, there are explanations as to what each command does in the Jupyter Notebook.

### model-details.md
This file.

### README.md
The README.

### requirements.txt
The software that should be installed before running this pipeline.

### sample-yi-camera-recording.pcap
A sample pcap file for demonstration that can be used to predict the amount of device activity based on the traffic in the file.

### traffic/
A directory with raw pcap data from several devices.
