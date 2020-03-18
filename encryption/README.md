# Encryption Analysis

Encryption Analysis calculates the entropies of data flows and classifies each flow as either encrypted, text, media, or unknown.

## Setup

The system should have **wireshark/tshark** installed; the versions that our machines have tested to be working are **v2.6.7** and **v2.6.8**.

We use python3 unless otherwise specified.

## Usage
The Jupyter Notebook [analyze_one_pcap.ipynb](analyze_one_pcap.ipynb) provides steps to parse a pcap file and label each flow as one of the four data types (encrypted, text, media, unknown).

`encryption.sh` is an equivalent to the Jupyter Notebook, which can be run directly in the terminal.

```
Usage: ./encryption.sh in_pcap out_csv ek_json

Example (run sample pcap): ./encryption.sh samples/traffic.pcap output/traffic.csv output/traffic.json
```
The sample code intends to demonstrate how we processed a single file. One should adapt the code in their clusters environment to proccess the whole dataset (traffic of 34,586 experiments). 

## Input

- `in_pcap` - The path to the input pcap file.
- `out_csv` - The path to the output CSV file.
- `ek_json` - The path to the intermediate JSON file.

## Output
The script first runs TShark with the input pcap file. TShark decodes the pcap file and dumps the results in the JSON file. Analysis is performed on the JSON file, which produces the CSV file.

