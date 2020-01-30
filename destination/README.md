# Traffic Analyser

This version relies on version Python 3.6 (tested on Python 3.6.3).

It is strongly suggested that one uses the following virtual environment:
```
sudo apt-get install virtualenv
sudo apt-get install libpcap-dev libpq-dev
sudo apt-get install python3-dev
sudo apt-get install python3.6-tk
sudo apt-get install gcc

virtualenv -p python3.6 env3
source env3/bin/activate
```

(Most of the) Following packages are required to run the code:
````
pip install numpy
pip install scipy
pip install pyshark
pip install geoip2
pip install matplotlib
pip install dpkt
pip install pycrypto
pip install IPy
pip install pcapy
pip install scapy
pip install Impacket
pip install mysql-connector-python-rf
pip install pandas
pip install tldextract
pip install python-whois
pip install ipwhois
pip install psutil
````

`fetch_passport.py` is used to map IP addresses to a country using Passport web service. 

Go to https://dev.maxmind.com/geoip/geoip2/geolite2/ to create a free account to download the GeoLite2 databases. In this directory, create a new directory called `geoipdb` and move `GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb` into this new directory.

Traffic analyser plots various types of graphs using various types of data.

Basic usage:
```
python analyse.py -i INPUT_FILE.pcap -m MAC_ADDRESS [-g GRAPH_TYPE -p PROTOCOL_TYPE [-l LOCATION_RETRIEVAL_METHOD]]
```

It is possible to specify several `-g` options. All `-g` options must be specified last, i.e. no other paramaters can be added after that.

`GRAPH_TYPE` can currently be one of the following: StackPlot, LinePlot, ScatterPlot, BarPlot, PiePlot, BarHPlot

`PROTOCOL_TYPE` is a comma separated list of protocols that should be analysed. It is in the format `PROTOCOL-[snd|rcv]`, which stands for "sent" and "received" traffic of the given protocol.

All traffic is included in the "eth" (ethernet) protocol, so to analyse all sent and received traffic, the option should be `eth-snd,eth-rcv`. To include only icmp traffic, one can use
`icmp-snd,icmp-rcv`.

`LOCATION_RETRIEVAL_METHOD` specifies how an IP address should be mapped to a host or a country. Currently supported options are: Country, Host, TSharkHost, RipeCountry, IP.

- *Country* - uses the Geo IP Database to map an IP into a Country.
- *Host* - uses reverse DNS lookup on an IP address. It also tries to extract only the domain name from the reverese lookup so all Google, Amazon AWS, etc. domains are groupped. 
- *TSharkHost* - uses the list produced by the `tshark` utility, which extracts hosts from the `.pcap` file. If a domain is not found, reverse DNS lookup is used.
- *RipeCountry* - uses Ripe.net API to find the location of an IP. If it fails, the Geo IP Database is used.

The following is an example of usage of the script to plot:
- a Scatter plot for all sent and received traffic
- a Horizontal Bar plot for the number of packets sent/received to/from each IP address
- a Horizontal Bar plot for traffic sent/received to/from each country using Ripe geolocation
- a Stack plot showing all sent and received IP traffic

```
python analyse.py -i netatmp_companion.pcap -m 64:bc:c:80:7e:1f -g ScatterPlot -p eth-snd,eth-rcv -g BarHPlot -l IP -p eth-snd,eth-rcv -g BarHPlot -l RipeCountry -p eth-snd,eth-rcv -g StackPlot -p ip-snd,ip-rcv 
```
