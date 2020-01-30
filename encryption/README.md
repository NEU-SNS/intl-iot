## Encryption Analysis Base Code

The Jupyter Notebook [analyze_one_pcap.ipynb](analyze_one_pcap.ipynb) provides steps to parse a pcap file and label each flow as one of the four data types (encrypted, text, media, unknown).

`encryption.sh` is an equivalent to the Jupyter Notebook, which can be run directly in the terminal. To analyze the sample data, run the following command:

```
./encryption.sh samples/traffic.pcap output/traffic.csv output/traffic.json
```

The sample code intends to demonstrate how we processed a single file. One should adapt the code in their clusters environment to proccess the whole dataset (traffic of 34,586 experiments).    

### Prerequisite

The system should have **wireshark/tshark** installed; the versions that our machines have tested to be working are **v2.6.7** and **v2.6.8**.     

We use python3 unless otherwise specified.
