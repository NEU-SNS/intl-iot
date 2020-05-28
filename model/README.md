# Models for Identifying Device Activity (Content Analysis)

Content Analysis generates a machine learning model that can predict the device activity given the network traffic of that device.

## Setup
Python 3.6 is required to run this code. Please follow the steps under General Setup in [Getting_Started.md](../Getting_Started.md#general-setup) before continuing.

Install the dependencies: `pip install -r requirements.txt`

## Information about the Model
For an explanation about the machine learning models: [model_details.md](model_details.md)

Definition of the device activity: tag name 
[gdoc exp](https://docs.google.com/document/d/1_s6brtocKG0zpdTVNWOxZZdJ1WSkJKKw9gbZh_32WJU/edit)

## Usage
The Jupyter Notebook [model_sample.ipynb](model_sample.ipynb) is a step-by-step guide that shows how to train a model using network traffic and how to use the model to classify (predict) a new traffic observed.

`model.sh` is an equivalent to the Jupyter Notebook, which can run directly in the terminal.

Usage: `./model.sh [OPTION]...`

Example: `./model.sh -i exp_list.txt -rn -v yi-camera -l knn -p yi_camera_sample.pcap -o results.csv`

### Input
There are several options which one can choose from. The default options have been set to run with the provided dataset.

#### Options:

`-i EXP_LIST` - The path to the text file containing filepaths to input pcap files to generate the models. To see the format of this text file, please see the `exp_list.txt` section of [model_details.md](model_details.md#exp_listtxt). Default is `exp_list.txt`.

`-t IMD_DIR` - The path to the directory where the script will create and put decoded pcap files. Default is `tagged-intermediate/us/`.

`-f FEAT_DIR` - The path to the directory where the script will create and put statistically-analyzed files. Default is `features/us/`.

`-m MODELS_DIR` - The path to the directory where the script will create and put generated models. Default is `tagged-models/us/`.

`-d` - Generate a model using the DBSCAN algorithm.

`-k` - Generate a model using the *k*-means algorithm.

`-n` - Generate a model using the *k*-nearest neighbors (KNN) algorithm.

`-r` - Generate a model using the random forest (RF) algorithm.

`-s` - Generate a model using the spectral clustering algorithm.

`-p IN_PCAP` - The path to the pcap file with unknown device activity that a model will use for prediction. Default is `yi_camera_sample.pcap`.

`-v DEV_NAME` - The name of the device that generated the data in `IN_PCAP`. This argument should match the name of a `device_name` directory (see the `exp_list.txt` section in [model_details.md](model_details.md#exp_listtxt)). Default is `yi-camera`.

`-o OUT_CSV` - The path to a CSV file to write the results of predicting the device activity in `IN_PCAP`. Default is `results.csv`.

#### Notes
- If no algorithm is specified, all five algorithms will be used to generate models.
- All directories and `OUT_CSV` will be generated if they currently do not exist.

### Output
This script produces a CSV file that contains the prediction of the state of the device given the network traffic in `IN_PCAP`. If the CSV exists, the script will overwrite it. Several intermediate files and directories are also produced, as described above.

The CSV file has six headings. Their meanings are listed below:

- `ts` - The Unix timestamp at which data was first recorded to `IN_PCAP`.
- `ts_end` - The Unix timestamp at which recording was stopped to `IN_PCAP`.
- `ts_delta` - The time difference between each frame capture.
- `num_pkt` - The number of packets in `IN_PCAP`
- `state` - The predicted state that the device was in when `IN_PCAP` was created.
- `device` - The input into the `-v` option.

For more information about the files and directories in this section, see [model_details.md](model_details.md#scripts).

