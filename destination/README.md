# Destination Analysis

Destination Analysis determines the organizations that traffic travels to and the amount of traffic going to and from those organizations.

## Setup
Before starting, go to https://dev.maxmind.com/geoip/geoip2/geolite2/ to create a free account to download the GeoLite2 databases. In this directory, create a new directory called `geoipdb/` and move `GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb` into this new directory.

## Usage
```
Usage: python analyze.py -i INPUTFILE {-m MACADDR | -d DEVICE} [Options] [-g PLOT -p PROTOCOL [Graph Options]] ...

Example: python analyze.py -i iot-data/uk/echodot/voice/2019-04-26_17:12:55.23s.pcap -d echodot -o output.csv

Example: python analyze.py -i iot-data/us/appletv/local_menu/2019-04-10_18:07:36.25s.pcap -m 7c:61:66:10:46:18 -f figoutput/ -g StackPlot -p eth-snd,eth-rcv -g LinePlot -p eth-snd,eth-rcv

Example: python analyze.py -i iot-data/uk/echodot/voice/2019-04-26_17:12:55.23s.pcap -d echodot -o output.csv -g LinePlot -p eth-snd,eth-rcv -g BarPlot -p eth-snd,eth-rcv
```
### Input
There are required arguments as well as several optional arguments which one can choose from. Below is a summary of all the options.

```
Options:
  --version             Show program's version number and exit.
  -h, --help            Show this help message and exit.
  -i INPUTFILE, --inputFile=INPUTFILE
                        An input PCAP file.
  -m MACADDR, --mac=MACADDR
                        MAC Address of the device used to create the data in 
                        the input file.
  -d DEVICE, --device=DEVICE
                        Name of the device used to create the data in the input
                        file.
  -c DEVICELIST, --deviceList=DEVICELIST
                        List containing all devices along with their MAC addresses.
                        Default=aux/devices_uk.txt
  -a IPADDR, --ip=IPADDR
                        IP Address of the device used to create the date in the
                        input file.
  -f FIGDIR, --figDir=FIGDIR
                        Directory to save plots. Default=figures/
  -t, --noTimeShift     Do not perform time shift.
  -s HOSTSFILE, --hostsFile=HOSTSFILE
                        File produced by tshark extracting hosts from the
                        pcacp file.
  -b LAB, --lab=LAB     Lab name.
  -e EXPERIMENT, --experiment=EXPERIMENT
                        Experiment name.
  -n NETWORK, --network=NETWORK
                        Network name.
  -o OUTPUTFILE, --outputFile=OUTPUTFILE
                        Output CSV file. Default=experiment.csv
  --findDiff            Find domains which do not reply.

  Graph Options:
    -g PLOT, --graph=PLOT
                        Type of graph to plot. Choose from StackPlot, LinePlot,
                        ScatterPlot, BarPlot, PiePlot, or BarHPlot. Specify
                        multiple of this option to plot multiple graphs.
    -p PROTOCOL, --protocol=PROTOCOL
                        The protocols that should be analyzed. Should be specified
                        in the format `send_protocol,receive_protocol`. This option
                        must be specified after each -g option used.
    -l IPLOC, --ipLoc=IPLOC
                        The method to map an IP address to a host or country.
                        Choose from Country, Host, IP, RipeCountry, or TSharkHost.
    -r IPATTR, --ipAttr=IPATTR
                        The IP packet attribute to display. Choose from either
                        addrPacketSize or addrPacketNum.
```
Required options:
- The -i options is required. This is the path to the input pcap file to be processed.
- The MAC address of the device whose traffic is recorded in the pcap file is also needed. Inputting the MAC address can be done in two ways:
  - Input the MAC address using the -m option.
  - Input the device name in the -d option, and input the file name to a list of devices using the -c option. The list of devices is a text file with a different device on a new line. Each line follows the format: `[MAC address] [Device name]` Ex. `90:71:92:8a:f5:e4 appletv`

All other options are optional.

If graphs are to be outputted, each graph should be specified using its own -g option. Any -p, -l, or -r option specified will be applied to the closest preceding -g option. Note that the -p option is required for each -g option used. Also note that all graph options must be specified at the end of the command; non-graph options cannot come after a -g option.

More information about the graph options:
`GRAPH_TYPE`, -g, can be one of the following:

- `StackPlot` - Stack Plot
- `LinePlot` - Line Plot
- `ScatterPlot` - Scatter Plot
- `BarPlot` - Bar Plot
- `PiePlot` - Pie Plot
- `BarHPlot` - Horizontal Bar Plot

`PROTOCOL_TYPE`, -p, is a comma separated list of protocols that should be analyzed. It is in the format `[snd|rcv]`, which stands for "sent" and "received" traffic of the given protocol.

All traffic is included in the "eth" (ethernet) protocol, so to analyze all sent and received traffic, the option should be `eth-snd,eth-rcv`. To include only icmp traffic, one can use
`icmp-snd,icmp-rcv`.

`LOCATION_RETRIEVAL_METHOD`, -l, specifies how an IP address should be mapped to a host or a country. Supported options are: `Country`, `Host`, `IP`, `RipeCountry`, or `TSharkHost`. The -l option is only needed when a pie plot is specified for the -g option.

- `Country` - uses the Geo IP Database to map an IP address into a country.
- `Host` - uses reverse DNS lookup on an IP address. It also tries to extract only the domain name from the reverese lookup so all Google, Amazon AWS, etc. domains are grouped.
- `IP` - uses the IP address directly.
- `RipeCountry` - uses Ripe.net API to find the location of an IP address. If it fails, the Geo IP Database is used.
- `TSharkHost` - uses the list produced by the `tshark` utility, which extracts hosts from the `.pcap` file. If a domain is not found, reverse DNS lookup is used.

### Output
When analyze.py is run, a CSV containing an analysis of the input pcap file is produced. By default, the CSV is stored in `experiment.csv`. However, the output file name can be changed by using the -o option. If the requested output file name already exists, the program will append the new data instead of overwriting.

The CSV file has 15 headings. Their meanings are listed below:

- `device` - the input into the -d option.
- `ip` - the IP address of the packets being analyzed.
- `host` - the domain name of the IP address. If not found, the IP address is used.
- `host_full` - the full domain name including the subdomain. If not found, the IP address is used.
- `traffic_snd` - the number of bytes of packets sent.
- `traffic_rcv` - the number of bytes of packets received.
- `packet_snd` - the number of packets sent.
- `packet_rcv` - the number of packets received.
- `country` - the country code of the country that the IP address belongs to. If not found, "XX" is displayed.
- `party` - is currently always "0".
- `lab` - the input into the -b option.
- `experiment` - the input into the -e option.
- `network` - the input into the -n option.
- `input_file` - the input pcap file while the data was generated from.
- `organization` - the organization that the IP address belongs to. If not found, "N/A" is displayed.

If graphs are produced, they will be stored in the `figures/` directory by default. The output directory can be changed by using the -f option. Each time analyze.py is run, exactly one PNG file is produced if one or more -g options are specified. The PNG file contains all the graphs specified. The name of the PNG file is the argument given into the -i option followed by the type(s) of graphs produced.

## Current Issues
This script is still being developed. Therefore, there are still a few issues. The information above conveys how the script should function ideally, but it may not completely do so. Known issues are listed below:

- Pie plot does not function properly. Please do not use PiePlot as an argument for the -g option.
- RipeCountry does not function properly because of a missing SQL Database. Please do not use RipeCountry for the -l option.
- `icmp-snd,icmp-rcv` may not work for the -p option.
