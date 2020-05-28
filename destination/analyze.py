""" Scripts processing pcap files and generating text output and figures """

import os
import sys
import pyshark
import re
import argparse

import numpy as np
import matplotlib.pyplot as plt
from scipy import signal

#from trafficAnalyzer import *  #Import statement below, after package files are checked

__author__ = "Roman Kolcun"
__copyright__ = "Copyright 2019"
__credits__ = ["Roman Kolcun"]
__license__ = "GPL"
__version__ = "2.0"
__maintainer__ = "Roman Kolcun"
__email__ = "roman.kolcun@imperial.ac.uk"
__status__ = "Development"

#Updated by Derek Ng in 2020

#File paths
path = sys.argv[0]
destDir = os.path.dirname(path)
if destDir == "":
    destDir = "."
trafficAnaDir = destDir + "/trafficAnalyzer"
consts = trafficAnaDir + "/Constants.py"
dataPres = trafficAnaDir + "/DataPresentation.py"
dev = trafficAnaDir + "/Device.py"
dnsTrack = trafficAnaDir + "/DNSTracker.py"
init = trafficAnaDir + "/__init__.py"
ip = trafficAnaDir + "/IP.py"
node = trafficAnaDir + "/Node.py"
stat = trafficAnaDir + "/Stats.py"
util = trafficAnaDir + "/Utils.py"
geoDir = destDir + "/geoipdb"
geoDbCity = geoDir + "/GeoLite2-City.mmdb"
geoDbCountry = geoDir + "/GeoLite2-Country.mmdb"

files = [consts, dataPres, dev, dnsTrack, init, ip, node, stat, util]


RED = "\033[31;1m"
END = "\033[0m"

print("Running %s..." % path)


#Check that traffic analyzer package has all files and correct permissions
errors = False
if not os.path.isdir(trafficAnaDir):
    errors = True
    print("%s%s: Error: The \"%s/\" directory is missing.\n"
            "     Make sure it is in the same directory as %s.%s"
            % (RED, path, trafficAnaDir, path, END), file=sys.stderr)
else:
    if not os.access(trafficAnaDir, os.R_OK):
        errors = True
        print("%s%s: Error: The \"%s/\" directory does not have read permission.%s"
                % (RED, path, trafficAnaDir, END), file=sys.stderr)
    if not os.access(trafficAnaDir, os.X_OK):
        errors = True
        print("%s%s: Error: The \"%s/\" directory does not have execute permission.%s"
                % (RED, path, trafficAnaDir, END), file=sys.stderr)
if errors:
    exit(1)

for f in files:
    if not os.path.isfile(f):
        errors = True
        print("%s%s: Error: The script \"%s\" cannot be found.\n"
                "     Please make sure it is in the same directory as \"%s\".%s"
                % (RED, path, f, path, END), file=sys.stderr)
    elif not os.access(f, os.R_OK):
        errors = True
        print("%s%s: Error: The script \"%s\" does not have read permission.%s"
                % (RED, path, f, END), file=sys.stderr)

if errors:
    exit(1)

from trafficAnalyzer import *


usage_stm = """
Usage: python3 {prog_name} -i IN_PCAP {{-m MAC_ADDR | -d DEV}} [OPTION]... [-g PLOT -p PROTO [GRAPH_OPTION]...]...

Performs destination analysis on a pcap file. Produces a CSV file detailing the
organizations that traffic in the PCAP files has been to and the number of
packets that were sent and received from those organizations. The program also
can produce graphs of this data.

Example: python3 {prog_name} -i iot-data/us/appletv/local_menu/2019-04-10_18:07:36.25s.pcap -m 7c:61:66:10:46:18 -g StackPlot -p eth-snd,eth-rcv -g LinePlot -p eth-snd,eth-rcv

Options:
  -i IN_PCAP  path to the input pcap file to be analyzed; option required
  -m MAC_ADDR MAC address of the device that generated the data in IN_PCAP;
                option required if DEV not specified
  -d DEV      name of the device used to generate the data in IN_PCAP;
                option required if MAC_ADDR not specified
  -c DEV_LIST path to a text file containing the names of devices along with
                the devices' MAC addresses; each device is on its own line,
                with each line having the format: "[MAC_ADDR] [DEVICE]"
                (Default = aux/devices_uk.txt)
  -a IP_ADDR  IP address of the device used to create the date in IN_PCAP
  -s HOSTS    path to a file produced by TShark extracting hosts from
                IN_PCAP
  -b LAB      name of the lab that IN_PCAP was generated in
  -e EXP      name of the experiment that IN_PCAP is a part of
  -w NETWORK  name of the network
  -t          do not perform a time shift
  -n          find domains which do not reply
  -f FIG_DIR  path to a directory to place generated plots; will be generated
                if it does not currently exist (Default = figures/)
  -o OUT_CSV  path to the output CSV file; if it exists, results will be
                appended, else, it will be created (Default = results.csv)
  -h          print this usage statement and exit

Graph options:
  -g PLOT  type of graph to plot; choose from StackPlot, LinePlot, ScatterPlot,
             BarPlot, PiePlot, or BarHPlot; PiePlot currently does not function
             properly; specify multiple of this option to plot multiple graphs
  -p PROTO protocols that should be analyzed; should be specified in the format 
             "[send_protocol],[receive_protocol]"; this option must be specified 
             after each -g option
  -l IPLOC method to map an IP address to a host or country; choose from Country,
             Host, IP, RipeCountry, or TSharkHost; RipeCountry currently does not
             function properly
  -r IPATT IP packet to display; choose from either addrPacketSize or addrPacketNum

Notes:
 - Only graph options can be specified after the first -g argument used (i.e.
     regular options can only be specified before the first -g option).
 - Each -g option used generates one graph. To generate more than one plot,
     specify additional -g options.
 - The -p, -l, and -r options modify the plot specified by the nearest preceding
     -g option.
 - All plots specified will be placed in one PNG file named:
     "[sanitized_IN_PCAP_path]_[plot_names].png"

For more information, see the README.""".format(prog_name=path)

#isError is either 0 or 1
def print_usage(isError):
    if isError == 0:
        print(usage_stm)
    else:
        print(usage_stm, file=sys.stderr)

    exit(isError)

def find_invalid_goptions(args):
    #Prints an error message if there are options other than -p, -l, or -r among the graph options
    done = False
    for arg in args:
        if arg[0] == '-':
            if arg not in ("-g", "-p", "-l", "-r"):
                done = True
                print("%s%s: Error: The \"%s\" option is after the \"-g\" option.%s"
                        % (RED, path, arg, END), file=sys.stderr)
    if done:
        print("%s    Only the \"-p\", \"-l\", and \"-r\" options may follow a \"-g\" option.\n"
                "    All other options must come before the first \"-g\" option.%s"
                % (RED, END), file=sys.stderr)
    
        print_usage(1)

if __name__ == "__main__":
    #Check that GeoLite2 databases exist and have proper permissions
    errors = False
    if not os.path.isdir(geoDir):
        errors = True
        print("%s%s: Error: The \"%s\" directory is missing.%s"
                % (RED, path, geoDir, END), file=sys.stderr)

    if not errors:
        if not os.access(geoDir, os.R_OK):
            errors = True
            print("%s%s: Error: The \"%s\" directory does not have read permission.%s"
                    % (RED, path, geoDir, END), file=sys.stderr)
        if not os.access(geoDir, os.X_OK):
            errors = True
            print("%s%s: Error: The \"%s\" directory does not have execute permission.%s"
                    % (RED, path, geoDir, END), file=sys.stderr)

    if not errors:
        if not os.path.isfile(geoDbCity):
            errors = True
            print("%s%s: Error: The \"%s\" database is missing.%s"
                    % (RED, path, geoDbCity, END), file=sys.stderr)
        if not os.path.isfile(geoDbCountry):
            errors = True
            print("%s%s: Error: The \"%s\" database is missing.%s"
                    % (RED, path, geoDbCountry, END), file=sys.stderr)
        if errors:
            print("%s    Please go to the README for instructions to download the databases.\n"
                    "    If the databases are already downloaded, please make sure they are\n"
                    "    in the correct directory.%s" % (RED, END), file=sys.stderr)
        
    if not errors:
        if not os.access(geoDbCity, os.R_OK):
            errors = True
            print("%s%s: Error: The script \"%s\" does not have read permission.%s"
                    % (RED, path, geoDbCity, END), file=sys.stderr)
        if not os.access(geoDbCountry, os.R_OK):
            errors = True
            print("%s%s: Error: The script \"%s\" does not have read permission.%s"
                    % (RED, path, geoDbCountry, END), file=sys.stderr)

    if errors:
        exit(1)


    #Main options
    parser = argparse.ArgumentParser(usage=usage_stm, add_help=False)
    parser.add_argument("-i", dest="inputFile")
    parser.add_argument("-m", dest="macAddr", default="")
    parser.add_argument("-d", dest="device", default="")
    parser.add_argument("-c", dest="deviceList", default=destDir+"/aux/devices_uk.txt")
    parser.add_argument("-a", dest="ipAddr")
    parser.add_argument("-s", dest="hostsFile")
    parser.add_argument("-b", dest="lab", default="")
    parser.add_argument("-e", dest="experiment", default="")
    parser.add_argument("-w", dest="network", default="")
    parser.add_argument("-t", dest="noTimeShift", action="store_true", default=False)
    parser.add_argument("-n", dest="findDiff", action="store_true", default=False)
    parser.add_argument("-f", dest="figDir", default=destDir+"/figures")
    parser.add_argument("-o", dest="outputFile", default=destDir+"/results.csv")
    parser.add_argument("-h", dest="help", action="store_true", default=False)

    #Graph Options
    graphParser = argparse.ArgumentParser(usage=usage_stm)
    graphParser.add_argument("-g", dest="plot")
    graphParser.add_argument("-p", dest="protocol", default="")
    graphParser.add_argument('-l', dest="ipLoc", default="")
    graphParser.add_argument('-r', dest="ipAttr", default="")


    #Parse Arguments
    start = False
    options = [] #Main Options
    graphs = [] #Graph Options
    args = [] #Tmp
    for arg in sys.argv:
        if arg == '-g' and not start: #Main Options
            args.pop(0)
            options = parser.parse_args(args)
            if options.help:
                print_usage(0)
            start = True
            args = []
            args.append(arg)
        elif arg == '-g' and start: #One set of graph options
            find_invalid_goptions(args)
            gopts = graphParser.parse_args(args)
            if gopts.plot == "PiePlot":
                print("***PiePlot currently does not function properly. Please choose a different"
                        " plot.\n   Currently available plots: StackPlot, LinePlot, ScatterPlot,"
                        " BarPlot, BarHPlot", file=sys.stderr)
                exit(0)
            graphs.append(gopts)
            args = []
            args.append(arg)
        else: #Append arg to temporary array
            args.append(arg)

    if not start: #Main Options (when no graph options exist)
        args.pop(0)
        options = parser.parse_args(args)
        if options.help:
            print_usage(0)
    else: #Last set of graph options
        find_invalid_goptions(args)
        gopts = graphParser.parse_args(args)
        if gopts.plot == "PiePlot":
            print("***PiePlot currently does not function properly. Please choose a different"
                    " plot.\n   Currently available plots: StackPlot, LinePlot, ScatterPlot,"
                    " BarPlot, BarHPlot", file=sys.stderr)
            exit(0)
        graphs.append(gopts)

    if options.macAddr != "":
        options.macAddr = Device.Device.normaliseMac(options.macAddr)


    #Error checking command line args
    done = False
    if options.inputFile == None:
        print("%s%s: Error: Pcap input file (-i) required.%s" % (RED, path, END), file=sys.stderr)
        done = True
    elif not options.inputFile.endswith(".pcap"):
        print("%s%s: Error: The input file should be a pcap (.pcap) file.\n    Received \"%s\".%s"
                % (RED, path, options.inputFile, END), file=sys.stderr)
        done = True
    elif not os.path.isfile(options.inputFile):
        print("%s%s: Error: The input file \"%s\" does not exist.%s"
                % (RED, path, options.inputFile, END), file=sys.stderr)
        done = True

    if options.hostsFile == "":
        options.hostsFile = options.inputFile

    if not options.outputFile.endswith(".csv"):
        print("%s%s: Error: The output file should be a CSV (.csv) file.\n    Received \"%s\".%s"
                % (RED, path, options.outputFile, END), file=sys.stderr)
        done = True

    noMACDevice = False
    validDeviceList = True
    if options.macAddr == "" and options.device == "":
        print("%s%s: Error: Either the MAC address (-m) or device (-d) must be specified.%s"
                % (RED, path, END), file=sys.stderr)
        done = True
        noMACDevice = True
    else:
        if options.macAddr == "":
            if not options.deviceList.endswith(".txt"):
                print("%s%s: Error: Device list must be a text (.txt) file.\n    Received \"%s\"%s"
                        % (RED, path, options.deviceList, END), file=sys.stderr)
                done = True
                validDeviceList = False
            elif not os.path.isfile(options.deviceList):
                print("%s%s: Error: Device list file \"%s\" does not exist.%s"
                        % (RED, path, options.deviceList, END), file=sys.stderr)
                done = True
                validDeviceList = False
        else:
            options.macAddr = options.macAddr.lower()
            if not re.match("([0-9a-f]{2}[:]){5}[0-9a-f]{2}$", options.macAddr):
                print("%s%s: Error: Invalid MAC address \"%s\". Valid format: xx:xx:xx:xx:xx:xx%s"
                        % (RED, path, options.macAddr, END), file=sys.stderr)
                done = True

    if validDeviceList:
        devices = Device.Devices(options.deviceList)
        if options.macAddr == "" and not noMACDevice:
            if not devices.deviceInList(options.device):
                print("%s%s: Error: The device \"%s\" does not exist in the device list \"%s\".%s"
                        % (RED, path, options.device, options.deviceList, END), file=sys.stderr)
                done = True
            else:
                options.macAddr = devices.getDeviceMac(options.device)

    plotTypes = ["StackPlot", "LinePlot", "ScatterPlot", "BarPlot", "PiePlot", "BarHPlot"]
    ipLocTypes = ["", "Country", "Host", "TSharkHost", "RipeCountry", "IP"]
    ipAttrTypes = ["", "addrPacketSize", "addrPacketNum"]
    for graph in graphs:
        if graph.plot not in plotTypes:
            print("%s%s: Error: \"%s\" is not a valid plot type.\n"
                    "    Must be either \"StackPlot\", \"LinePlot\", \"ScatterPlot\","
                    " \"BarPlot\", \"PiePlot\", or \"BarHPlot\".%s"
                    % (RED, path, graph.plot, END), file=sys.stderr)
            done = True
        else:
            if graph.protocol == "":
                print("%s%s: Error: A protocol (-p) must be specified for \"%s\".%s"
                        % (RED, path, graph.plot, END), file=sys.stderr)
                done = True
            if graph.ipLoc not in ipLocTypes:
                print("%s%s: Error: Invalid IP locator method \"%s\" for \"%s\".\n"
                        "    Must be either \"Country\", \"Host\", \"TSharkHost\","
                        " \"RipeCountry\", or \"IP\".%s"
                        % (RED, path, graph.ipLoc, graph.plot, END), file=sys.stderr)
                done = True
            if graph.ipAttr not in ipAttrTypes:
                print("%s%s: Error: Invalid IP Attribute \"%s\" for \"%s\".\n"
                        "    Must be either \"addrPacketSize\" or \"addrPacketNum\".%s"
                        % (RED, path, graph.ipAttr, graph.plot, END), file=sys.stderr)
                done = True

    if done:
        print_usage(1)
    #End error checking


    print("Processing PCAP file...")
    cap = pyshark.FileCapture(options.inputFile, use_json = True)
    Utils.sysUsage("PCAP file loading")

    try:
        if options.noTimeShift:
            baseTS = 0
            cap[0]
        else:
            baseTS = float(cap[0].frame_info.time_epoch)
    except KeyError:
        print("File {} does not contain any packets.".format(options.inputFile))
        sys.exit()

    nodeId = Node.NodeId(options.macAddr, options.ipAddr)
    nodeStats = Node.NodeStats(nodeId, baseTS, devices, options)
    print("Processing packets...")
    for packet in cap:
        nodeStats.processPacket(packet)

    Utils.sysUsage("Packets processed")
    #print(sorted(list(dict.keys(nodeStats.stats.stats))))

    print("Mapping IP to host...")
    ipMap = IP.IPMapping()
    ipMap.extractFromFile(options.inputFile)
    ipMap.loadOrgMapping(destDir + "/aux/ipToOrg.csv")
    ipMap.loadCountryMapping(destDir + "/aux/ipToCountry.csv")

    Utils.sysUsage("TShark hosts loaded")

    print("Generating output CSV...")
    de = DataPresentation.DomainExport(nodeStats.stats.stats,
            ipMap, options, geoDbCity, geoDbCountry)
    if options.findDiff:
        de.loadDiffIPFor("eth")
    else:
        de.loadIPFor("eth")
    de.loadDomains()
    de.exportDataRows()
    #sys.exit()

    Utils.sysUsage("Data exported")

    if len(graphs) != 0:
        print("Generating plots...")
        pm = DataPresentation.PlotManager(nodeStats.stats.stats,
                graphs, options, geoDbCity, geoDbCountry)
        pm.ipMap = ipMap
        pm.generatePlot()

        Utils.sysUsage("Plots generated")

    print("\nDestintaion analysis finished.")

