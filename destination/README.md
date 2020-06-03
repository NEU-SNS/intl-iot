# Destination Analysis

Destination Analysis determines the organizations that traffic travels to and the amount of traffic going to and from those organizations.

## Setup
Before starting, go to https://dev.maxmind.com/geoip/geoip2/geolite2/ to create a free account to download the GeoLite2 databases. In this directory, create a new directory called `geoipdb/` and move `GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb` into this new directory.

## Usage

Usage: `python3 analyze.py -i IN_DIR {-m MAC_ADDR | -d DEV} [OPTION]... [-g PLOT -p PROTO [GRAPH_OPTION]...]...`

Example: `python3 analyze.py -i iot-data/uk/echodot/voice/ -d echodot -o output.csv -n 4`

Example: `python3 analyze.py -i iot-data/us/appletv/ -m 7c:61:66:10:46:18 -f figout/ -g StackPlot,LinePlot -p eth.eth,eth.eth`

Example: `python3 analyze.py -i iot-data/uk/echodot/ -d echodot -g BarPlot,BarHPlot -p eth.eth,eth.eth -l ,Country -r ,addrPcktNum`

### Input

There are required arguments as well as several optional arguments which one can choose from. Below is a summary of all the options:

#### Options

`-i IN_DIR` - The path to the directory containing input pcap file to be analyzed. **Option required.**

`-m MAC_ADDR` - MAC address of the device that generated the data in `IN_DIR`. **Option required if `DEV` not specified.**

`-d DEV` - The name of the device used to generate the data in `IN_DIR`. **Option required if `MAC_ADDR` not specified.**

`-c DEV_LIST` - The path to a text file containing the names of devices along with the devices' MAC addresses. Each device is on its own line, with each line having the format: `[MAC_ADDR] [DEVICE]`. Default is `aux/devices_uk.txt`.

`-a IP_ADDR` - IP address of the device used to create the date in `IN_DIR`.

`-s HOSTS` - The path to a file produced by TShark extracting hosts from `IN_DIR`.

`-b LAB` - The name of the lab that the pcap files in `IN_DIR` were generated in.

`-e EXP` - The name of the experiment that the pcap files in `IN_DIR` are a part of.

`-w NETWORK` - The name of the network.

`-t` - Do not perform a time shift.

`-y` - Find domains which do not reply.

`-f FIG_DIR` - The path to a directory to place generated plots. Directory will be generated if it does not currently exist. Default is `figures/`.

`-o OUT_CSV` - The path to the output CSV file. If it exists, results will be appended, else, it will be created. Default is `results.csv`.

`-n NUM_PROC` - The number of processes to use to analyze the pcap files. Default is `1`.

`-h` - Print the usage statement and exit.

#### Graph options

To produce more than one graph, use commas to separate arguments. See the [notes](#Notes) section for examples.

`-g PLOTS` - A comma-delimited list of the types of graphs to plot. Choose from `StackPlot`, `LinePlot`, `ScatterPlot`, `BarPlot`, `PiePlot`, or `BarHPlot`. `PiePlot` currently does not function properly.

`-p PROTOS` - A comma-delimited list of protocols that should be analyzed. **For each plot specified in `PLOTS`,** there should be two protocols specified in the following period-delimited format: `[send_protocol].[receive_protocol]`.

`-l IPLOCS` - A comma-delimited list of methods to map an IP address to a host or country. Choose from `Country`, `Host`, `IP`, `RipeCountry`, or `TSharkHost`. `RipeCountry` currently does not function properly. **This option affects only pie plots and horizontal bar plots.**

`-r IPATTS` - A comma-delimited list of IP packet attributes to display. Choose from either `addrPacketSize` or `addrPacketNum`. **This option affects only pie plots and horizontal bar plots.**

#### Notes

Required options:
- The `-i` option is required. This is the path to a directory containing input pcap files to be processed.
- The MAC address of the device whose traffic is recorded in the pcap files is also needed. Inputting the MAC address can be done in two ways:
  - Input the MAC address directly using the `-m` option.
  - Input the device name in the `-d` option, and input the file name to a list of devices using the `-c` option. The list of devices is a text file with a different device on a new line. Each line follows the format: `[MAC address] [Device name]` Ex. `90:71:92:8a:f5:e4 appletv`. An example file is `aux/devices_uk.txt`.

All other options are optional.

More information about the graph options:

An argument for the `-g` option can be one of the following:

- `StackPlot` - Stack Plot
- `LinePlot` - Line Plot
- `ScatterPlot` - Scatter Plot
- `BarPlot` - Bar Plot
- `PiePlot` - Pie Plot
- `BarHPlot` - Horizontal Bar Plot

An argument for the `-p` option consists of send protocol and receive protocol delimited by a period (`.`). It is in the format `[snd].[rcv]`, which stands the for "sent" and "received" traffic of the given protocol.

All traffic is included in the "eth" (Ethernet) protocol, so to analyze all sent and received traffic, the option should be `eth,eth`. To include only ICMP traffic, one can use `icmp,icmp`.

An argument for the `-l` option specifies how an IP address should be mapped to a host or a country. This option affects only pie plots and horizontal bar plots. Supported options are:

- `Country` - Uses the Geo IP Database to map an IP address into a country.
- `Host` - Uses reverse DNS lookup on an IP address. It also tries to extract only the domain name from the reverse lookup so all Google, Amazon AWS, etc. domains are grouped.
- `IP` - Uses the IP address directly.
- `RipeCountry` - Uses Ripe.net API to find the location of an IP address. If it fails, the Geo IP Database is used.
- `TSharkHost` - Uses the list produced by TShark, which extracts hosts from the pcap files. If a domain is not found, reverse DNS lookup is used.

An argument for the `-r` option specifies the attribute to plot in a graph. This option affects only pie plots or horizontal bar plots. Supported options are:

- `addrPcktSize` - Plot the packet sizes in a pcap file.
- `addrPcktNum` - Plot the number of packets in a pcap file.

Example: If the graph options specified are `-g LinePlot,BarHPlot -p eth.eth,eth.eth -l ,Country -r ,addrPcktNum`, then the following plots are produced:

- A line plot with Ethernet as both the send and receive protocols.
- A horizontal bar plot with Ethernet as both the send and receive protocols using the country method to map IP addresses to hosts and plotting number of packets.

### Output

When `analyze.py` is run, a CSV containing an analysis of the input pcap files is produced. By default, the CSV is stored in `results.csv`. However, the output file name can be changed by using the `-o` option. If the requested output file name already exists, the program will append the new data instead of overwriting.

The CSV file has 16 headings. Their meanings are listed below:

- `ts` - The Unix timestamp of when the first packet of the input file was generated.
- `device` - The input into the `-d` option.
- `ip` - The IP address of the packets being analyzed.
- `host` - The domain name of the IP address. If not found, the IP address is used.
- `host_full` - The full domain name including the subdomain. If not found, the IP address is used.
- `traffic_snd` - The number of bytes of packets sent.
- `traffic_rcv` - The number of bytes of packets received.
- `packet_snd` - The number of packets sent.
- `packet_rcv` - The number of packets received.
- `country` - The country code of the country that the IP address belongs to. If not found, "XX" is displayed.
- `party` - Is currently always "0".
- `lab` - The input into the `-b` option.
- `experiment` - The input into the `-e` option.
- `network` - The input into the `-n` option.
- `input_file` - The input pcap file name from which the data was generated from.
- `organization` - The organization that the IP address belongs to. If not found, "N/A" is displayed.

If graphs are produced, they will be stored in the `figures/` directory by default. The output directory can be changed by using the `-f` option. Each time `analyze.py` is run, exactly one PNG file is produced if one or more `-g` options are specified. The PNG file contains all the graphs specified. The name of the PNG file is a sanitized version of the pcap file followed by the type(s) of graphs produced.

## Current Issues

This script is still being developed. Therefore, there are still a few issues. The information above conveys how the script should function ideally, but it may not completely do so. Known issues are listed below:

- Pie plots currently cannot be generated. Please do not use `PiePlot` as an argument for the `-g` option.
- The ripe country method does not function properly because of a missing SQL database. Please do not use `RipeCountry` for the `-l` option.

