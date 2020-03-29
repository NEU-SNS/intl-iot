# Getting Started
This document provides a step-by-step starting guide to perform analysis with the code accompanying the paper "Information Exposure From Consumer IoT Devices." This document is contains four sections: General Setup, Destination Analysis, Encryption Analysis, and Content Analysis. **In-depth information can be found in the READMEs for each pipeline.**

## General Setup
### System Setup
A good operating system to use is Linux. Specifically, this guide was written using Ubuntu 18.04. The code might work using a MAC terminal, but there could be issues, such as with TShark. The code has not been tested on Windows. Users on a Windows or MAC platform are encouraged to install an Ubuntu virtual machine. [VirtualBox](https://www.virtualbox.org/) and [VMWare](https://www.vmware.com/) are two popular virtual machine softwares. If you are using a virtual machine, please make sure to allocate enough disk space. If you are using the dataset from this study, it is recommended that 30 GB be allocated.

### Environment Setup
1) Clone the Git Repo: `git clone https://github.com/NEU-SNS/intl-iot`
2) Create a Python 3.6 environment to run the scripts:
```
sudo apt-get install virtualenv libpcap-dev libpq-dev python3-dev python3.6-tk gcc
virtualenv -p python3.6 env
source env/bin/activate
```
3) Install the following packages:
```
pip install numpy scipy pyshark geoip2 matplotlib dpkt pycrypto IPy pcapy scapy Impacket mysql-connector-python-rf pandas tldextract python-whois ipwhois psutil
```

### Download Datasets
If you would like to use the dataset from this study, follow the directions below to obtain a copy. If you have your own data, you may skip this section. **All examples shown uses this dataset.**

1) Go to the [Mon(IoT)r Lab site](https://moniotrlab.ccis.neu.edu/imc19/) to request access to the dataset. You will have to agree to a data sharing agreement because of sensitive information that may still be in the data.
2) Once you have access, download the four tar archives.
3) Untar each of them: `tar -zxvf [tar archive]`.
4) Move the directories created by `iot-data.tgz` and `iot-idle.tgz` into the `destination/` directory.
5) Move the directories created by `iot-model.tgz` into the `model/` directory.
6) Move the directory created by `synthetic.tgz` into the `encryption/validation/` directory.

## Destination Analysis
Destination Analysis analyzes where the network traffic in input pcap files has been to. A CSV file containing the analysis is outputted. Optional plots to visualize the data can also be outputted.

### Setup
1) Download the GeoLite2 city and country databases by creating a free account at https://dev.maxmind.com/geoip/geoip2/geolite2/.
2) Untar the tar archives. In the untarred country directory, you will find a database named `GeoLite2-Country.mmdb`. In the untarred city directory, you will, similarly, find a database named `GeoLite2-City.mmdb`.
3) `cd` into the `intl-iot/destination/` directory.
4) Make a directory to hold the databases: `mkdir geoipdb/`.
5) Move the two database files listed above into the `geoipdb/` directory.

### Run Pipeline
Very basic usage: `python analyze.py -i INPUTFILE -m MACADDR [-g PLOT -p PROTOCOL]`

For input, very basic usage requires the path to an input pcap file (-i) and a MAC address of the device from which the data in the input pcap file was generated from (-m). The -g option produces a graph, and the -p option modifies how the graph is created. **Graph related options (-g and -p in this example) must come at the very end of the command.**

For output, a CSV called `experiment.csv` is generated. Information about the contents of this file can be found in the [Destination README](./destination/README.md). Optional graphs can be produced using the -g option.

Example 1: `python analyze.py -i iot-data/us/appletv/local_menu/2019-04-10_18:07:36.25s.pcap -m 7c:61:66:10:46:18 -g StackPlot -p eth-snd,eth-rcv`
   - Output: A CSV file named `experiment.csv` is produced in the current directory (`destination/`), and a stack plot is produced in a newly created `figures/` directory.

More than one plot can be created by specifying more than one -g option at the end of the command. All other options following the -g option modifies that graph until a new -g option is reached, at which point a new graph is created.

Example 2: `python analyze.py -i iot-data/us/appletv/local_menu/2019-04-10_18:07:36.25s.pcap -m 7c:61:66:10:46:18 -g StackPlot -p eth-snd,eth-rcv -g LinePlot -p eth-snd,eth-rcv`
   - Output: A CSV file named `experiment.csv` is produced in the current directory, and an image in the `figures/` directory is produced containing a stack plot and a line plot.

As an alternative to the MAC address, a device (-d option) and a device list (-c option) can be given. The device list is a text file containing the MAC of several devices. Each line is formatted as follows: `[MAC] [Device name]`. An example device list is `aux/devices_uk.txt`.

Example 3: `python analyze.py -i iot-data/uk/echodot/voice/2019-04-26_17:12:55.23s.pcap -d echodot -c aux/devices_uk.txt -o out_csv.csv -f out_figs/ -g BarPlot -p eth-snd,eth-rcv`
   - Output: The script uses the Echo Dot MAC address in `aux/devices_uk.txt` to perform analysis. A CSV named `out_csv.csv` is created. A bar plot is produced in the newly created `out_figs/` directory.

## Encryption Analysis
Encryption Analysis determines the entropy of packets in an input pcap file and classifies the data as either encrypted, text, media, or unknown.

`cd` into the `intl-iot/encryption/` directory.

Usage: `./encryption.sh in_pcap out_csv ek_json`

For input, this script requires the path to an input pcap file and paths to where an output CSV file and an intermediate JSON file should be created.

For output, a CSV file containing the results is generated. An intermediate JSON file is also generated. The JSON file is parsed, and the parsed information is written to the CSV file. More information about the contents of the CSV file can be found in the [Encryption README](./encryption/README.md).

Example: `./encryption.sh sample.pcap sample.csv sample.json`
   - Output: The input pcap file `sample.pcap` is run through TShark to produce `sample.json`. This JSON file is analyzed to produce `sample.csv`.

## Content Analysis
Content Analysis takes in several pcap files with known device activity to create a machine learning model. The model can then predict the device activity of a different pcap file based on the network traffic.

### Setup
1) `cd` into the `intl-iot/model/` directory.
2) Install the required libraries: `pip install -r requirements.txt`.

If you are using the datasets from this study, you may skip to the next section. If you are using your own datasets, please follow the steps below to properly structure your input pcap files.

3) You will need several pcap files to create a machine learning model; the more files the better. The activity of the device when each pcap file was created should be known. Put the pcap files in the following directory structure, based on the device and activity type:
```
{root_experiment_director(y|ies)}/{device_name}/{device_activity}/{pcap_file}.pcap
```
See the `exp_list.txt` section in [model/model_details.md](model/model_details.md#exp_listtxt) for more info.

4) Create a text file containing the paths to each input pcap file, with each path on a new line. You may name the text file whatever you would like.

### Run Pipeline
Usage: `./model.sh exp_list intermediate_dir features_dir model_dir device_name pcap_path result_path`

For input, this pipeline requires several items:
- `exp_list` - the text file that contains paths to input pcap files that will be used to generate the models. If you are using your own dataset, this is the file you created in Step 4.
- `intermediate_dir` - the path to the directory where the script will create and put decoded pcap files.
- `features_dir` - the path to the directory where the script will create and put analyzed files.
- `model_dir` - the path to the directory where the script will create and put generated models.
- `device_name` - the name of the device that generated the data in the pcap file of unknown device activity. This argument should match the name of a `device_name` directory (see Step 3).
- `pcap_path` - the path to a pcap file of unknown device activity.
- `result_path` - the path to a CSV file to output the results.

Note: If you are using your own datasets, you do not need to create any of the directories nor the output CSV file listed above; the script will generate them. If you are using the provided dataset, the directories are already included; use the example below.

For output, a CSV file is produced, which contains the device activity prediction. For more information about the contents of the CSV file, see the output section in [model/README.md](model/README.md#output).

Example: `./model.sh exp_list.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera yi_camera_sample.pcap sample.csv`
   - Output: TShark decodes the pcap files listed in `exp_list.txt`, which is written to the `tagged-intermediate/us/` directory. Features are then extracted to the `features/us/` directory. Using the features, a machine learning model is created in the `tagged-models/us/` directory. The pcap file `yi_camera_sample.pcap` is then sent into the model and results are produced to `sample.csv`.

For more information about the files and directories in this section, see [model/model_details.md](model/model_details.md). For step by step instructions on how this pipeline works, see [model/model_sample.ipynb](model/model_sample.ipynb).
