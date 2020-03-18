# Getting Started
This document aims to provide a quick step-by-step starting guide to performing analysis with the code accompanying the paper "Information Exposure From Consumer IoT Devices." This document is split into four sections: general setup, destination analysis, encryption analysis, and content analysis. In depth information can be found in the READMEs for each pipeline.

## General Setup
### System Setup
A good operating system to use to run this code is Linux. Specifically, this guide was written using Ubuntu 18.04. The code could possibly work through a MAC terminal, although there possibly could be issues, such as with TShark. The code has not been tested on Windows. Users on a Windows or MAC platform are encouraged to install an Ubuntu virtual machine. [VirtualBox](https://www.virtualbox.org/) and [VMWare](https://www.vmware.com/) are two popular virtual machine softwares. If you are using a virtual machine, please make sure to allocate enough space. If you are using the dataset from this study, it is recommended that 30 GB be allocated.

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
If you would like to use the dataset from this study, follow the directions below to obtain a copy. If you have your own data, you may skip this section.

1) Go to the [Mon(IoT)r Lab site](https://moniotrlab.ccis.neu.edu/imc19/) to request access to the dataset. You will have to agree to a data sharing agreement because of sensitive information that may still be in the data.
2) Once you have access, download the four tar archives.
3) Untar each of them: `tar -zxvf [tar archive]`
4) Move the directories created by `iot-data.tgz` and iot-idle.tgz` into the `destination/` directory.
5) Move the directories created by `iot-model.tgz` into the `model/` directory.
6) Move the directory created by `synthetic.tgz` into the `encryption/validation` directory.

## Destination Analysis
Destination Analysis analyses where the network traffic in input pcap files has been to. A CSV file containing the analysis is outputted. Optional plots to visualize the data can also be outputted.

### Setup
1) Download the GeoLite2 city and country databases by creating a free account at https://dev.maxmind.com/geoip/geoip2/geolite2/.
2) Untar the tar archives. In the untarred country directory, you will find a database named `GeoLite2-Country.mmdb`. In the untarred city directory, you will, similarly, find a database named `GeoLite2-City.mmdb`.
3) `cd` into the `intl-iot/destination/` directory
4) Make directory to hold the databases: `mkdir geoipdb/`
5) Move the two database files listed above into the `geoipdb/` directory.

### Run Pipeline
Very basic usage: `python analyse.py -i INPUTFILE -m MACADDR [-g PLOT -p PROTOCOL]`
Very basic usage requires the an input pcap file and a MAC address of the device from which the data in the input pcap file was generated from. The -g option produces a graph, and the -p option modifies how the graph is created. Graph related options (-g and -p in this example) must come at the very end of the command.

Example 1: `python analyse.py -i iot-data/us/appletv/local_menu/2019-04-10_18:07:36.25s.pcap -m 7c:61:66:10:46:18 -g StackPlot -p eth-snd,eth-rcv`
   - Output: A CSV file named `experiment.csv` is produced in the current directory (`destination/`), and a stack plot is produced in a newly created `figures/` directory.

More than one plot can be created by specifying more than one -g option at the end of the command.

Example 2: `python analyse.py -i iot-data/us/appletv/local_menu/2019-04-10_18:07:36.25s.pcap -m 7c:61:66:10:46:18 -g StackPlot -p eth-snd,eth-rcv -g LinePlot -p eth-snd,eth-rcv`
   - Output: A CSV file named `experiment.csv` is produced in the current directory, and an image in the `figures/` directory is produced containing a stack plot and a line plot.

As an alternative to the MAC address, a device and a device list can be given. The device list is a text file that with a different device on each line. Each line is formatted as follows: `[MAC] [Device name]`. An example device list is `aux/devices_uk.txt`. In the command, the MAC address of the given device will be used.

Example 3: `python analyse.py -i iot-data/uk/echodot/voice/2019-04-26_17:12:55.23s.pcap -d echodot -c aux/devices_uk.txt -o out_csv.csv -f out_figs/ -g BarPlot -p eth-snd,eth-rcv`
   - Output: The script uses the Echo Dot MAC address in `aux/devices_uk.txt` to perform analysis. A CSV named `out_csv.csv` is created. A bar plot is produced in the newly created `out_figs/` directory.

## Encryption Analysis
Encryption Analysis determines the entropy of packets in an input pcap file and classifies the data as either encrypted, text, media, or unknown.

`cd` into the `intl-iot/encryption/` directory.

Usage: `./encryption.sh in_pcap out_csv ek_json`

Example: `./encryption.sh samples/traffic.pcap output/traffic.csv output/traffic.json`
   - Output: The input pcap file `samples/traffic.pcap` is run through TShark to produce `output/traffic.json`. This JSON file is analyzed to produce `output/traffic.csv`.

## Content Analysis
Content Analysis takes in several pcap files to create a machine learning model. The model can then be used to predict the amount of device activity from a different pcap file that can be inferred based on the network data in that pcap file.

Usage: `./model.sh exp_list intermediate_dir features_dir model_dir device_name pcap_path result_path`

Example: `./model.sh list_exp.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera sample-yi-camera-recording.pcap sample-result.csv`
   - Output: TShark decodes the pcap files listed in `list_exp.txt` and writes the output to the `tagged-intermediate/us/` directory. Features are then extracted and placed in the `features/us/` directory. Using the features, a machine learning model is created and placed in the `tagged-models/us/` directory. The pcap file `sample-yi-camera-recording.pcap` is then sent into the model and the results are produced to `sample-result.csv`.

