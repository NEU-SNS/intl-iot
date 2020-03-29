# Detailed Descriptions for Content Analysis Scripts
Below is a detailed description about the files and directories in this section.

## Scripts

### model.sh
Usage: `./model.sh exp_list intermediate_dir features_dir model_dir device_name pcap_path result_path`

Example: `./model.sh exp_list.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera yi_camera_sample.pcap sample.csv`

This is the main script of the content analysis pipeline. The scripts listed below are parts of this pipeline. The main goal of this pipeline is to use machine learning to predict the device activity given the network traffic of that device. First, the pipeline needs to create a model using machine learning. The raw network traffic (provided in several pcap files with known device activity) is decoded into human-readable raw data. This raw data is then statistically analyzed and sent into an algorithm for training. Once trained, a model will be generated for each device. A pcap file with unknown device activity can be put through the same process of decoding it into human-readable data and statistically analyzing it. The analyzed data can then be used to predict the device activity based on the network traffic.

Input:
- `exp_list` - the text file that contains paths to input pcap files to generate the models. To see the format of this text file, please see the [exp_list.txt](exp_listtxt) section below).
- `intermediate_dir` - the path to the directory where the script will create and put decoded pcap files.
- `features_dir` - the path to the directory where the script will create and put analyzed files.
- `model_dir` - the path to the directory where the script will create and put generated models.
- `device_name` - the name of the device that generated the data in the pcap file of unknown device activity. This argument should match the name of a `device_name` directory (see the [exp_list.txt](#exp_listtxt) section below).
- `pcap_path` - the path to the pcap file of unknown device activity.
- `result_path` - the path to a CSV file to write the results.

Output:
This script produces a CSV file that contains the prediction of the state of the device given the device's network traffic. If the CSV exists, the script will overwrite it. Several intermediate files and directories are also produced, as described above.

- `ts` - the unix timestamp at which data was first recorded to the input pcap file.
- `ts_end` - the unix timestamp at which recording was stopped to the input pcap file.
- `ts_delta` - the time difference between each frame capture.
- `num_pkt` - the number of packets in the input pcap file.
- `state` - the predicted state that the device was in when the pcap file was created.
- `device` - the device name that the data in the pcap file was recorded on.

### raw2intermediate.sh
Usage: `./raw2intermediate.sh exp_list out_intermediate_dir`

Example: `./raw2intermediate.sh exp_list.txt tagged-intermediate/us/`

This script decodes data in pcap files listed in the `exp_list` text file into human-readable text files using tshark.

Input:
- `exp_list` - the text file that contains paths to input pcap files to generate the models. To see the format of this text file, please see the `exp_list.txt` section of [model_details.md](model_details.md#exp_listtxt).
- `out_intermediate_dir` - the path to the directory where the script will create and put decoded pcap files.

Output:
A plain-text file will be produced for every input pcap file. Each output file contains a translation of the raw input file into human-readable form. The raw data output is tab-delimited and is in .txt format. If an output file already exists, tshark will not run with its corresponding input file, and the existing output file will remain. If tshark cannot read the input file, no output file will be produced.

### extract_tbp_features.py
Usage: `python extract_tbp_features.py in_intermediate_dir out_features_dir`

Example: `python extract_tbp_features.py tagged-intermediate/us/ features/us/`

This script uses the human-readable pcap data output from `raw2intermediate.sh` to perform data analysis.

Input:
- `in_intermediate_dir` - the path to a directory containing text files of human-readable raw pcap data.
- `out_features_dir` - the path to the directory to write the analyzed CSV files

Output:
Each valid input file (.txt) in the input directory will be analyzed, and an CSV file containing statistcal analysis will be produced in a `cache/` directory in the specified output directory. After every input file is processed, all the CSV files of each device will be concatenated together in a separate CSV file, which will be placed in the specified output directory. If a device already has a concatenated CSV file, no analysis will occur for that device, and the existing file will remain. If a device does not have a concatenated CSV file, the program will regenerate any cache files, as necessary, and the cache files of the device will be concatenated. If an input file is not a text file (.txt.), no output will be produced for that file.

### train_rf_models.py
Usage: `python train_rf_models.py in_features_dir out_model_dir`

Example: `python train_rf_models.py features/us/ tagged-models/us/`

This script trains analyzed pcap data and generates a model that can predict device activity.

Input:
- `in_features_dir` - path to a directory containing CSV files that have analyzed pcap data.
- `out_model_dir` - path to the directory to place the generated model.

Output:
The script will generate three files for each device. One file contains the model, which can be used to predict device activity. A second file contains a list of experiment types. These two files are used in the next step of the pipeline. A third file contains the training accuracy scores for each device. If a device already has these three files in the output directory, they will not be regenerated. However, if one or more of those files are missing, they will be regenerated.

### predict.py
Usage: `python predict.py device_name pcap_path result_file model_dir`

Example: `python predict.py yi-camera yi_camera_sample.pcap sample.csv tagged-models/us/ `

The script uses a model to predict the device activity given a pcap file from that device.

Input:
- `device_name` - the name of the device that the pcap file contains network traffic of. This argument should match the name of a `device_name` directory (see the [exp_list.txt](#exp_listtxt) section below).
- `pcap_path` - path to the pcap file of unknown network activity.
- `result_path` - path to a CSV file to write results.
- `model_dir` - the path to the directory containing the model of `device_name`.

Output:
The script decodes the input pcap file and stores the decoded data in a `user-intermediates/` directory. If a file containing the decoded data already exists, the file will not be regenerated. The script then outputs a CSV file containing the predictions made by the model and the decoded data. If the output file already exists, the script will overwrite the file.

## Non-scripts

### exp_list.txt
A list of the paths to input pcap files with known device activity. The input files are used to generate the machine learning models; the more input files, the better the model. The directory structure of the input pcap files should be: `{root_experiment_director(y|ies)}/{device_name}/{activity_type}/input.pcap`. For example, `traffic/us/yi-camera/power/2019-04-25_19:28:58.154s.pcap`:

- `traffic/us/` is the root experiment directory.
- `yi-camera/` is the device directory.
- `power/` is the activity type directory.
- `2019-04-25_19:28:58.154s.pcap` is the input pcap file.

Each path should be on a new line.

### model_info.md
A file which further explains the models.

### model_sample.ipynb
A Jupyter Notebook that contains runnable code with the same commands as `model.sh`. However, there are explanations as to what each command does in the Jupyter Notebook.

### model_details.md
This file.

### README.md
The README.

### requirements.txt
The software that should be installed before running this pipeline.

### yi_camera_sample.pcap
A sample pcap file for demonstration that can be used to predict the device activity based on the traffic in the file.

### traffic/
A directory with sample pcap files to generate a model. Note: To obtain these files, please follow the directions in the Download Datasets section in [Getting_Started.md](../Getting_Started.md#download-datasets)
