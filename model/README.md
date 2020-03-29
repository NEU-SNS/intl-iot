# Models for Identifying Device Activity (Content Analysis)

Content Analysis generates a machine learning model that can predict the device activity given the network traffic of that device.

## Setup
Python 3.6 is required to run this code. Please follow the steps under General Setup in [Getting_Started.md](../Getting_Started.md#general-setup) before continuing.

Install the dependencies: `pip install -r requirements.txt`

## Information about the Model
For an explanation about the machine learning models: [model_info.md](model_info.md)

Definition of the device activity: tag name 
[gdoc exp](https://docs.google.com/document/d/1_s6brtocKG0zpdTVNWOxZZdJ1WSkJKKw9gbZh_32WJU/edit)

## Usage
The Jupyter Notebook [model_sample.ipynb](model_sample.ipynb) is a step-by-step guide that shows how to train a model using network traffic and how to use the model to classify (predict) a new traffic observed.

`model.sh` is an equivalent to the Jupyter Notebook, which can run directly in the terminal. To ananalyze the example data provided, run the following command:

Usage: `./model.sh exp_list intermediate_dir features_dir model_dir device_name pcap_path result_path`

Example: `./model.sh exp_list.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera yi_camera_sample.pcap sample.csv`

### Input
- `exp_list` - the text file that contains paths to input pcap files to generate the models. To see the format of this text file, please see the `exp_list.txt` section of [model_details.md](model_details.md#exp_listtxt).
- `intermediate_dir` - the path to the directory where the script will create and put decoded pcap files.
- `features_dir` - the path to the directory where the script will create and put analyzed files.
- `model_dir` - the path to the directory where the script will create and put generated models.
- `device_name` - the name of the device that generated the data in the pcap file of unknown device activity. This argument should match the name of a `device_name` directory (see the `exp_list.txt` section in [model_details.md](model_details.md#exp_listtxt)).
- `pcap_path` - the path to the pcap file of unknown device activity.
- `result_path` - the path to a CSV file to write the results.

### Output
This script produces a CSV file that contains the prediction of the state of the device given the network traffic in the input file. If the CSV exists, the script will overwrite it. Several intermediate files and directories are also produced, as described above.

The CSV file has six headings. Their meanings are listed below:

- `ts` - the unix timestamp at which data was first recorded to the input pcap file.
- `ts_end` - the unix timestamp at which recording was stopped to the input pcap file.
- `ts_delta` - the time difference between each frame capture.
- `num_pkt` - the number of packets in the input pcap file.
- `state` - the predicted state that the device was in when the pcap file was created.
- `device` - the device name that the data in the pcap file was recorded on.

For more information about the files and directories in this section, see [model_details.md](model_details.md).
