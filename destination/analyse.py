""" Scripts processing pcap files and generating text output and figures """

import os
import sys
import pyshark

import numpy as np
import matplotlib.pyplot as plt
from scipy import signal

import re

from trafficAnalyser import *

import argparse

__author__ = "Roman Kolcun"
__copyright__ = "Copyright 2019"
__credits__ = ["Roman Kolcun"]
__license__ = "GPL"
__version__ = "2.0"
__maintainer__ = "Roman Kolcun"
__email__ = "roman.kolcun@imperial.ac.uk"
__status__ = "Development"

usage_stm = """
Usage: analyse.py -i INPUTFILE {-m MACADDR | -d DEVICE} [Options] [-g PLOT -p PROTOCOL [Graph Options]] ...

Performs destination analysis on a PCAP file. Produces a CSV file detailing the organizations that traffic in the PCAP files has been to and the number of packets that were sent and received from those organizations. The program also can produce graphs of this data.

Example: python analyse.py -i iot-data/us/appletv/local_menu/2019-04-10_18:07:36.25s.pcap -m 7c:61:66:10:46:18 -g StackPlot -p eth-snd,eth-rcv -l IP -g LinePlot -p eth-snd,eth-rcv -l IP

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
  -a IPADDR, --ip=IPADDR
                        IP Address of the device used to create the date in the
                        input file.
  -f FIGDIR, --figDir=FIGDIR
                        Directory to save plots.
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
                        Output CSV file.
  --findDiff            Find domains which do not reply.

  Graph Options:
    -g PLOT, --graph=PLOT
                        Type of graph to plot. Choose from StackPlot, LinePlot,
                        ScatterPlot, BarPlot, PiePlot, or BarHPlot. Specify
                        multiple of this option to plot multiple graphs.
    -p PROTOCOL, --protocol=PROTOCOL
                        The protocols that should be analysed. Should be specified
                        in the format send_protocol,receive_protocol. This option
                        must be specified after each -g option used.
    -l IPLOC, --ipLoc=IPLOC
                        The method to map an IP address to a host or country.
                        Choose from Country, Host, IP, RipeCountry, or TSharkHost.
    -r IPATTR, --ipAttr=IPATTR
                        The IP packet attribute to display. Choose from either
                        addrPacketSize or addrPacketNum.
"""

def print_usage():
    print(usage_stm)
    exit(0)

def find_invalid_goptions(args):
    #Prints an error message if there are options other than -p, -l, or -r among the graph options
    done = False
    for arg in args:
        if arg[0] == '-':
            if arg not in ("-g", "-p", "-l", "-r"):
                done = True
                print("\033[31mError: The \"%s\" option is after the \"-g\" option.\033[39m" % arg)
    if done:
        print("\033[31mOnly the \"-p\", \"-l\", and \"-r\" options may follow a \"-g\" option. All other options must be placed before the first \"-g\" option.\033[39m")
        print_usage()

if __name__ == "__main__":
    print("Running %s..." % sys.argv[0])
    missingDb = False
    if not os.path.isfile("./geoipdb/GeoLite2-City.mmdb"):
        missingDB = True
        print("The GeoLite2-City.mmdb database is missing.")
    if not os.path.isfile("./geoipdb/GeoLite2-Country.mmdb"):
        missingDB = True
        print("The GeoLite2-Country.mmdb database is missing.")
    if missingDb:
        print("Please go to the README for instructions to download the databases. If you have already downloaded the databases, please place them in the geoipdb/ directory.")
        exit(0)

    #Main options
    print("Reading command line arguments...")
    parser = argparse.ArgumentParser(usage=usage_stm)
    parser.add_argument("-i", "--inputFile", dest="inputFile")
    parser.add_argument("-m", "--mac", dest="macAddr", default="")
    parser.add_argument("-d", "--device", dest="device", default="")
    parser.add_argument("-c", "--deviceList", dest="deviceList", default="aux/devices_uk.txt")
    parser.add_argument("-a", "--ip", dest="ipAddr")
    parser.add_argument("-f", "--figDir", dest="figDir", default="figures")
    parser.add_argument("-t", "--noTimeShift", dest="noTimeShift", action="store_true", default=False)
    parser.add_argument("-s", "--hostsFile", dest="hostsFile")
    parser.add_argument("-b", "--lab", dest="lab", default="")
    parser.add_argument("-e", "--experiment", dest="experiment", default="")
    parser.add_argument("-n", "--network", dest="network", default="")
    parser.add_argument("-o", "--outputFile", dest="outputFile", default="experiment.csv")
    parser.add_argument("--findDiff", dest="findDiff", action="store_true", default=False)

    #Graph Options
    graphParser = argparse.ArgumentParser(usage=usage_stm)
    graphParser.add_argument("-g", "--graph", dest="plot")
    graphParser.add_argument("-p", "--protocol", dest="protocol", default="")
    graphParser.add_argument('-l', "--ipLoc", dest="ipLoc", default="")
    graphParser.add_argument('-r', "--ipAttr", dest="ipAttr", default="")

    #Parse Arguments
    start = False
    options = [] #Main Options
    graphs = [] #Graph Options
    args = [] #Tmp
    for arg in sys.argv:
        if arg == '-g' and start == False: #Main Options
            args.pop(0)
            options = parser.parse_args(args)
            start = True
            args = []
            args.append(arg)
        elif arg == '-g' and start == True: #One set of graph options
            find_invalid_goptions(args)
            gopts = graphParser.parse_args(args)
            if gopts.plot == "PiePlot":
                print("***PiePlot currently does not function properly. Please choose a different plot. Currently available plots: StakPlot, LinePlot, ScatterPlot, BarPlot, BarHPlot")
                exit(0)
            graphs.append(gopts)
            args = []
            args.append(arg)
        else: #Append arg to temporary array
            args.append(arg)

    if start == False: #Main Options (when no graph options exist)
        args.pop(0)
        options = parser.parse_args(args)
    else: #Last set of graph options
        find_invalid_goptions(args)
        gopts = graphParser.parse_args(args)
        if gopts.plot == "PiePlot":
            print("***PiePlot currently does not function properly. Please choose a different plot. Currently available plots: StakPlot, LinePlot, ScatterPlot, BarPlot, BarHPlot")
            exit(0)
        graphs.append(gopts)

    if options.macAddr != "":
        options.macAddr = Device.Device.normaliseMac(options.macAddr)

    #Error checking command line args
    print("Performing error checking on command line arguments...")
    done = False
    if options.inputFile == None:
        print("\033[31mError: Pcap input file required.\033[39m")
        done = True
    elif not options.inputFile.endswith(".pcap"):
        print("\033[31mError: Pcap input file required. Received \"%s\"\033[39m" % options.inputFile)
        done = True
    elif not os.path.isfile(options.inputFile):
        print("\033[31mError: The input file \"%s\" does not exist.\033[39m" % options.inputFile)
        done = True

    if options.hostsFile == "":
        options.hostsFile = options.inputFile

    if not options.outputFile.endswith(".csv"):
        print("\033[31mError: The output file should be a .csv file. Received \"%s\".\033[39m" % options.outputFile)
        done = True

    noMACDevice = False
    validDeviceList = True
    if options.macAddr == "" and options.device == "":
        print("\033[31mError: Either the MAC address (-m) or device (-d) must be specified.\033[39m")
        done = True
        noMACDevice = True
    else:
        if options.macAddr == "":
            if not options.deviceList.endswith(".txt"):
                print("\033[31mError: Device list must be a text file (.txt). Received \"%s\"\033[39m" % options.deviceList)
                done = True
                validDeviceList = False
            elif not os.path.isfile(options.deviceList):
                print("\033[31mError: Device list file \"%s\" does not exist.\033[39m" % options.deviceList)
                done = True
                validDeviceList = False
        else:
            options.macAddr = options.macAddr.lower()
            if not re.match("([0-9a-f]{2}[:]){5}[0-9a-f]{2}$", options.macAddr):
                print("\033[31mError: Invalid MAC address \"%s\". Valid format: dd:dd:dd:dd:dd:dd\033[39m" % options.macAddr)
                done = True

    if validDeviceList:
        devices = Device.Devices(options.deviceList)
        if options.macAddr == "" and not noMACDevice:
            if not devices.deviceInList(options.device):
                print("\033[31mError: The device \"%s\" does not exist in the device list in \"%s\".\033[39m" % (options.device, options.deviceList))
                done = True
            else:
                options.macAddr = devices.getDeviceMac(options.device)

    plotTypes = ["StackPlot", "LinePlot", "ScatterPlot", "BarPlot", "PiePlot", "BarHPlot"]
    ipLocTypes = ["", "Country", "Host", "TSharkHost", "RipeCountry", "IP"]
    ipAttrTypes = ["", "addrPacketSize", "addrPacketNum"]
    for graph in graphs:
        if graph.plot not in plotTypes:
            print("\033[31mError: \"%s\" is not a valid plot type. Must be either \"StackPlot\", \"LinePlot\", \"ScatterPlot\", \"BarPlot\", \"PiePlot\", or \"BarHPlot\".\033[39m" % graph.plot)
            done = True
        else:
            if graph.protocol == "":
                print("\033[31mError: A protocol (-p) must be specified for \"%s\".\033[39m" % graph.plot)
                done = True
            if graph.ipLoc not in ipLocTypes:
                print("\033[31mError: Invalid IP locator method \"%s\" for \"%s\". Must be either \"Country\", \"Host\", \"TSharkHost\", \"RipeCountry\", or \"IP\".\033[39m" % (graph.ipLoc, graph.plot))
                done = True
            if graph.ipAttr not in ipAttrTypes:
                print("\033[31mError: Invalid IP Attribute \"%s\" for \"%s\". Must be either \"addrPacketSize\" or \"addrPacketNum\".\033[39m" % (graph.ipAttr, graph.plot))
                done = True

    if done:
        print_usage()
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
    ipMap.loadOrgMapping("aux/ipToOrg.csv")
    ipMap.loadCountryMapping("aux/ipToCountry.csv")

    Utils.sysUsage("TShark hosts loaded")

    print("Generating output CSV...")
    de = DataPresentation.DomainExport(nodeStats.stats.stats, ipMap, options)
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
        pm = DataPresentation.PlotManager(nodeStats.stats.stats, graphs, options)
        pm.ipMap = ipMap
        pm.generatePlot()

        Utils.sysUsage("Plots generated")

    sys.exit()

