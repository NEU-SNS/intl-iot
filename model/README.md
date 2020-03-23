# Models for Identifying Device Activity (Content Analysis)

Content Analysis generates a machine learning model that can predict the device activity given the network traffic of that device.

## Setup
Dependencies: pip3 install -r requirements.txt   
We need python3 to run the scripts. 

Download [Google Drive > iot-model.tgz](https://drive.google.com/open?id=1lMqZ5qx6ATqIIiLOdTYcSm6RliK1F7vA) (size = ~127MB) before running the Juypter Notebook.

## Information about the Model
More explanations on ML models: [Model.md](Model.md)

Definition of the device activity: tag name 
[gdoc exp](https://docs.google.com/document/d/1_s6brtocKG0zpdTVNWOxZZdJ1WSkJKKw9gbZh_32WJU/edit)

## Usage
[model_sample.ipynb](model_sample.ipynb) walks you through steps that trains a model from traffic of experiments and uses the model to classify (predict) a new traffic observed.

`model.sh` is an equivalent to the Jupyter Notebook, which can be run directly in the terminal. To ananalyze the example data provided, run the following command:

```
./model.sh list_exp.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera sample-yi-camera-recording.pcap sample-result.csv
```

### Input
- `exp_list`: The text file that contains paths to pcap files to analyze to generate the models. To see the format of this text file, please see the `list_exp.txt` section of [model-details.md](model-details.md).
- `intermediate_dir`: The path to the directory to place the decoded pcap files.
- `features_dir`: The path to the directory to place the analyzed files.
- `model_dir`: The path to the directory to place the generated models.
- `device_name`: The name of the device that generated the data in the pcap file that will be used to predict the amount of device activity. This should be the same name as the device directory (see the `list_exp.txt` section in [model-details.md](model-details..md) below) that the input pcap file is in.
- `pcap_path`: The path to the pcap file that will be used to predict the amount of device activity.
- `result_path`: The path to a CSV file to write the reslts.

### Output
This script produces a CSV file that contains the prediction of the state of the device given the network traffic in the input file. If the CSV exists, the script will overwrite it. Several intermediate files and directories are also produced, as described above.

The CSV file has six headings. Their meanings are listed below:

- `ts` - the unix timestamp at which data was first recorded to the input pcap file.
- `ts_end` - the unix timestamp at which recording was stopped to the input pcap file.
- `ts_delta` - the time difference between each frame capture.
- `num_pkt` - the number of packets in the input pcap file.
- `state` - the predicted state that the device was in when the pcap file was created.
- `device` - the device name that the data in the pcap file was recorded on.
