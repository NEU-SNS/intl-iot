# Detailed Descriptions for Content Analysis Models and Scripts

Below is a detailed description about the machine learning models, the files, and the directories in this section.

## Machine Learning Models to Detect Device Activity

### Problem Statement

For a specified device, given a sequence of network frames, what is the device activity?

Examples:
- device: amcrest-cam-wired
- network traffic: 10 minutes of network traffic
- device activity: one of
    - movement
    - power
    - watch_android
    - watch_cloud_android
    - watch_cloud_ios
    - watch_ios

**++ Cases**: the 10 minutes of traffic could have more than one activity.

### Machine Learning

During evaluation, we use following algorithms:
- RF:  [RandomForestClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html) (supervised)
- KNN: [KNeighborsClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.KNeighborsClassifier.html) (supervised)
- *k*-means: [MiniBatchKMeans](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.MiniBatchKMeans.html) (unsupervised)
- DBSCAN: [DBSCAN](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.DBSCAN.html) (unsupervised)

For the purpose of IMC submission, we do not consider unsupervised approaches (i.e. *k*-means, DBSCAN).

### Variables in sklearn:

N samples of M features of L classes
- X_features: features of N samples, N * M,
- y_labels: labels of N samples
- X_train: default 70% of N samples (shuffled)
- X_test: default 30% of N samples (shuffled)
- y_train: original encoded values, e.g. "watch_ios_on"
    - y_train_bin: onehot encoded, e.g. [0, 1, 0, 0] as watch_ios_on is the second in the .classes_
- y_test: original encoded values
    - y_test_bin: onehot encoded
    - y_test_bin_1d: encoded values
    - y_predicted: onehot encoded prediction of X_test
    - y_predicted_1d: encoded values
    - y_predicted_label: original values
- _acc_score: Trained with X_train,y_train; eval with X_test, y_test; refer to [accuracy_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.accuracy_score.html)
-  _complete: refer to [completeness_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.completeness_score.html#sklearn.metrics.completeness_score)
    > This metric is independent of the absolute values of the labels: a permutation of the class or cluster label values won’t change the score value in any way.
-  _silhouette: [silhouetee_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.silhouette_score.html#sklearn.metrics.silhouette_score)

## Scripts

### model.sh

#### Usage

Usage: `./model.sh [OPTION]...`

Example: `./model.sh -i exp_list.txt -rn -v yi-camera -l knn -p yi_camera_sample.pcap -o sample.csv`

This is the main script of the content analysis pipeline. The scripts listed below are parts of this pipeline. The main goal of this pipeline is to use machine learning to predict the device activity given the network traffic of that device. First, the pipeline needs to create a model using machine learning. The raw network traffic (provided in several pcap files with known device activity) is decoded into human-readable raw data. This raw data is then statistically analyzed and sent into an algorithm for training. Once trained, one or more models will be generated for each device. A pcap file with unknown device activity can be put through the same process of decoding it into human-readable data and statistically analyzing it. The analyzed data can then be used to predict the device activity based on the network traffic.

#### Input

`-i EXP_LIST` - The path to text file containing filepaths to the pcap files to be used to generate machine learning models. To see the format of this text file, please see the [exp_list.txt](#exp_listtxt) section below). Default is `exp_list.txt`.

`-t IMD_DIR` - The path to the directory where the script will create and put decoded pcap files. Default is `tagged-intermediate/us/`.

`-f FEAT_DIR` - The path to the directory where the script will create and put statistically-analyzed files. Default is `features/us/`.

`-m MODELS_DIR` - The path to the directory where the script will create and put generated models. Default is `tagged-models/us/`.

`-d` - Generate a model using the DBSCAN algorithm.

`-k` - Generate a model using the *k*-means algorithm.

`-n` - Generate a model using the *k*-nearest neighbors (KNN) algorithm.

`-r` - Generate a model using the random forest (RF) algorithm.

`-s` - Generate a model using the spectral clustering algorithm.

`-p IN_PATH` - The path to the pcap file with unknown device activity. Default is `yi_camera_sample.pcap`.

`-v DEV_NAME` - The name of the device that generated the data in `IN_PCAP`. This argument should match the name of a `device_name` directory (see the [exp_list.txt](#exp_listtxt) section below). Default is `yi-camera`.

`-l MODEL_NAME` - The name of the model to be used to predict the device activity of `IN_PCAP`.
Choose from `kmeans`, `knn`, or `rf`. The DBSCAN and spectral clustering algorithms cannot be us
ed for prediction. The model must also have been generated to be used. Default is `rf`.

`-o OUT_CSV` - The path to a CSV file to write the results of predicting the device activity of `IN_PATH`. Default is `sample.csv`.

`-h` - Display the usage statement and exit.

Notes: All directories and `OUT_CSV` will be generated if they currently do not exist. If no models are specified to be generated, all five models will be created.

#### Output

This script produces a CSV file that contains the prediction of the state of the device given the device's network traffic. If the CSV exists, the script will overwrite it. Several intermediate files and directories are also produced, as described above.

- `ts` - The Unix timestamp at which data was first recorded to `IN_PCAP`.
- `ts_end` - The Unix timestamp at which recording was stopped to `IN_PCAP`.
- `ts_delta` - The time difference between each frame capture.
- `num_pkt` - The number of packets in `IN_PCAP`.
- `state` - The predicted state that the device was in when `IN_PCAP` was created.
- `device` - The input into the `-v` option.

### raw2intermediate.sh

#### Usage

Usage: `./raw2intermediate.sh exp_list out_imd_dir`

Example: `./raw2intermediate.sh exp_list.txt tagged-intermediate/us/`

This script decodes data in pcap files listed in the `exp_list` text file into human-readable text files using TShark.

#### Input

`exp_list` - The text file that contains paths to input pcap files to generate the models. To see the format of this text file, please see the `exp_list.txt` section of [model_details.md](model_details.md#exp_listtxt).

`out_imd_dir` - The path to the directory where the script will create and put decoded pcap files. If this directory current does not exist, it will be generated.

#### Output

A plain-text file will be produced for every input pcap (.pcap) file. Each output file contains a translation of the raw input file into human-readable form. The raw data output is tab-delimited and is stored in a text (.txt) file.

If an output file already exists, TShark will not run with its corresponding input file, and the existing output file will remain. If TShark cannot read the input file, no output file will be produced.

### extract_features.py

#### Usage

Usage: `python3 extract_features.py in_imd_dir out_features_dir`

Example: `python3 extract_features.py tagged-intermediate/us/ features/us/`

This script uses the human-readable pcap data output from `raw2intermediate.sh` to perform data analysis.

#### Input

`in_imd_dir` - The path to a directory containing text files of human-readable raw pcap data.

`out_features_dir` - The path to the directory to write the analyzed CSV files. If this directory current does not exist, it will be generated.

#### Output

Each valid input text (.txt) file in the input directory will be analyzed, and a CSV file containing statistical analysis will be produced in a `cache/` directory in `out_features_dir`. After each input file is processed, all the CSV files of each device will be concatenated together in a separate CSV file, which will be placed in `out_features_dir`.

If a device already has a concatenated CSV file located in `out_features_dir`, no analysis will occur for that device, and the existing file will remain. If a device does not have a concatenated CSV file, the script will regenerate any cache files, as necessary, and the cache files of the device will be concatenated. If an input file is not a text (.txt) file, no output will be produced for that file.

### eval_models.py

#### Usage

Usage: `python3 eval_models.py -f IN_FEATURES_DIR -m OUT_MODELS_DIR [-dknrs]`

Example: `python3 eval_models.py -f features/us/ -m tagged-models/us/ -kn`

This script trains analyzed pcap data and generates one or more models that can predict device activity.

#### Input

`-f IN_FEATURES_DIR` - The path to a directory containing CSV files that have analyzed pcap data. This option is required.

`-m OUT_MODELS_DIR` - The path to the directory to place the generated model. If this directory currently does not exist, it will be generated. This option is required.

`-d` - Generate a model using the DBSCAN algorithm.

`-k` - Generate a model using the *k*-means algorithm.

`-n` - Generate a model using the *k*-nearest neighbors (KNN) algorithm.

`-r` - Generate a model using the random forest (RF) algorithm.

`-s` - Generate a model using the spectral clustering algorithm.

Note: If no model is chosen, all the models will be produced.

#### Output

The script will generate three files for each model specified. One file contains the model, which can be used to predict device activity. A second file contains a list of experiment types. These two files are used in the next step of the pipeline. A third file contains the training accuracy scores for each device. If a device already has these three files in the output directory, they will not be regenerated. However, if one or more of those files are missing, they will be regenerated.

### predict.py

#### Usage

Usage: `python3 predict.py pcap_path model_dir device_name model_name result_path`

Example: `python3 predict.py yi_camera_sample.pcap tagged-models/us/ yi-camera rf results.csv`

The script uses a model to predict the device activity given a pcap file from that device.

#### Input

`pcap_path` - The path to the pcap file with unknown device activity.

`model_dir` - The path to the directory containing the directories of the models.

`device_name` - The name of the device that generated the data in `pcap_path`. This argument should match the name of a `device_name` directory (see the [exp_list.txt](#exp_listtxt) section below).

`model_name` - The name of the model to be used to predict the device activity in `pcap_path`. Choose from `kmeans`, `knn`, or `rf`.

`result_path` - The path to a CSV file to write results. If this file does not currently exist, it will be generated.

#### Output

The script decodes the input pcap file and stores the decoded data in a `user-intermediates/` directory. If a file containing the decoded data already exists, the file will not be regenerated. The script then outputs a CSV file containing the predictions made by the selected model and the decoded data. If the output file already exists, the script will overwrite the file.

## Non-scripts

### exp_list.txt

A list of the paths to input pcap files with known device activity. The input files are used to generate the machine learning models; the more input files, the better the model. The directory structure of the input pcap files should be: `{root_experiment_director(y|ies)}/{device_name}/{activity_type}/input.pcap`. For example, `traffic/us/yi-camera/power/2019-04-25_19:28:58.154s.pcap`:

- `traffic/us/` is the root experiment directory.
- `yi-camera/` is the device directory.
- `power/` is the activity type directory.
- `2019-04-25_19:28:58.154s.pcap` is the input pcap file.

Each path should be on a new line.

### model_sample.ipynb

A Jupyter Notebook that contains runnable code with the same commands as `model.sh`. However, there are explanations as to what each command does in the Jupyter Notebook.

### model_details.md

This file. Provides detailed information about the models and the files in the content analysis pipeline.

### README.md

The README.

### requirements.txt

The software that should be installed before running this pipeline. To install, run:

```
pip install -r requirements.txt
```

### yi_camera_sample.pcap

A sample pcap file for demonstration that can be used to predict the device activity based on the traffic in the file.

### traffic/

A directory with sample pcap files to generate a model. Note: To obtain these files, please follow the directions in the Download Datasets section in [Getting_Started.md](../Getting_Started.md#download-datasets)

