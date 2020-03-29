## Validation of threshold for encryption classification

Go to https://moniotrlab.ccis.neu.edu/imc19/ to request the data set before running any scripts. Once accesss is granted, download `sythetic.tgz` and untar it to this directory.

**Prep.** `synthetic/f*.txt` are text from the IMC 2019 site. Run `mass_enc.sh` to generate encryted version in the same folder.

**Validation of symmetric.** To create some synthetic examples of encrypted vs. plaintext ASCII data sent over either TCP or UDP, we run a local server and a local client. For simplicity, we use a python socket for the communication, and we collect local network traffic on the port 12345 (encrypted) and 12346 (plain) by using wireshark/tshark, usually it is the lo0 interface. 

**Validation of various TLS ciphers.** We use the Python SSL library to test available cipher suites in a local machine. The list is not exhaustive; from what we see, the variance is relatively small. 

### Symmetric Encryption Traffic Sampling 
All the data has been generated to the `synthetic/` directory. If you want to add more experiments, follow steps for plain/encrypted traffic generation to add support for more encryption schemes and protocols. 

**Plain Traffic Generation**
1. Run the local server: `python socket_server.py 12346`
2. Run tshark collection: `tshark -i lo0 -w synthetic/plain.pcap`
3. Run `./mass_client_plain.sh`

**Encrypted Traffic Generation**   
1. Run the local server: `python socket_server.py 12345`
2. Run tshark collection: `tshark -i lo0 -w synthetic/enc.pcap`
3. Run `./mass_client_enc.sh`

### TLS Cipher Suites 
File: `synthetic/tls.pcap` contains the following TLS cipher suites:
```
TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```    

Steps to collect the above traffic yourself:  
1. Run tshark collection: `tshark -i lo0 -w synthetic/tls.pcap`
2. Run `./gen_ssl.sh` to iterate ciphers available in the machine 

### Extract and Collect Entropies    
1. `./mass_extract_compute.sh` takes in any .pcap file in the `sythetic/` directory for entropy computation. 
2. Update `slists.txt` to include whatever experiment traffic you generated.
3. `python synthetic_threshold.py`. Expected outcome from exisiting dataset is shown as below. Note that this is only one example using Fernet https://cryptography.io/en/latest/fernet/:

```
   data_type data_proto       avg       std        mi        ma
0  encrypted       data  0.730901  0.025577  0.673421  0.749331
1       text       data  0.546994  0.073246  0.350919  0.620695
```
