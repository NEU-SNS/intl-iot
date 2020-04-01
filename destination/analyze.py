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
destDir = os.path.dirname(sys.argv[0])
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


print("Running %s..." % sys.argv[0])


#Check that traffic analyzer package has all files and correct permissions
print("Checking files...")

errors = False
if not os.path.isdir(trafficAnaDir):
    errors = True
    print("%sError: The \"%s/\" directory is missing.%s" % (RED, trafficAnaDir, END))
    print("%s       Make sure it is in the same directory as %s.%s" % (RED, sys.argv[0], END))
else:
    if not os.access(trafficAnaDir, os.R_OK):
        errors = True
        print("%sError: The \"%s/\" directory does not have read permission.%s" % (RED, trafficAnaDir, END))
    if not os.access(trafficAnaDir, os.X_OK):
        errors = True
        print("%sError: The \"%s/\" directory does not have execute permission.%s" % (RED, trafficAnaDir, END))
if errors:
    exit(1)

for f in files:
    if not os.path.isfile(f):
        errors = True
        print("%sError: The script \"%s\" cannot be found.%s" % (RED, f, END))
        print("%s       Please make sure it is in the same directory as \"%s\".%s" % (RED, sys.argv[0], END))
    elif not os.access(f, os.R_OK):
        errors = True
        print("%sError: The script \"%s\" does not have read permission.%s" % (RED, f, END))

if errors:
    exit(1)

from trafficAnalyzer import *


usage_stm = """
Usage: {prog_name} -i INPUTFILE {{-m MACADDR | -d DEVICE}} [Options] [-g PLOT -p PROTOCOL [Graph Options]] ...

Performs destination analysis on a pcap file. Produces a CSV file detailing the
organizations that traffic in the PCAP files has been to and the number of
packetsthat were sent and received from those organizations. The program also
can produce graphs of this data.

Example: python {prog_name} -i iot-data/us/appletv/local_menu/2019-04-10_18:07:36.25s.pcap -m 7c:61:66:10:46:18 -g StackPlot -p eth-snd,eth-rcv -g LinePlot -p eth-snd,eth-rcv

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
                        The protocols that should be analyzed. Should be specified
                        in the format send_protocol,receive_protocol. This option
                        must be specified after each -g option used.
    -l IPLOC, --ipLoc=IPLOC
                        The method to map an IP address to a host or country.
                        Choose from Country, Host, IP, RipeCountry, or TSharkHost.
    -r IPATTR, --ipAttr=IPATTR
                        The IP packet attribute to display. Choose from either
                        addrPacketSize or addrPacketNum.
""".format(prog_name=sys.argv[0])

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
                print("%sError: The \"%s\" option is after the \"-g\" option.%s" % (RED, arg, END))
    if done:
        print("%s       Only the \"-p\", \"-l\", and \"-r\" options may follow a \"-g\" option.%s" % (RED, END))
        print("%s       All other options must be placed before the first \"-g\" option.%s" % (RED, END))
        print_usage()

if __name__ == "__main__":
    #Check that GeoLite2 databases exist and have proper permissions
    errors = False
    if not os.path.isdir(geoDir):
        errors = True
        print("%sError: The \"%s\" directory is missing.%s" % (RED, geoDir, END))

    if not errors:
        if not os.access(geoDir, os.R_OK):
            errors = True
            print("%sError: The \"%s\" directory does not have read permission.%s" % (RED, geoDir, END))
        if not os.access(geoDir, os.X_OK):
            errors = True
            print("%sError: The \"%s\" directory does not have execute permission.%s" % (RED, geoDir, END))

    if not errors:
        if not os.path.isfile(geoDbCity):
            errors = True
            print("%sError: The \"%s\" database is missing.%s" % (RED, geoDbCity, END))
        if not os.path.isfile(geoDbCountry):
            errors = True
            print("%sError: The \"%s\" database is missing.%s" % (RED, geoDbCountry, END))
        if errors:
            print("%s       Please go to the README for instructions to download the databases. If the%s" % (RED, END))
            print("%s       databases are already downloaded, please make sure they are in the correct directory.%s" % (RED, END))
        
    if not errors:
        if not os.access(geoDbCity, os.R_OK):
            errors = True
            print("%sError: The script \"%s\" does not have read permission.%s" % (RED, geoDbCity, END))
        if not os.access(geoDbCountry, os.R_OK):
            errors = True
            print("%sError: The script \"%s\" does not have read permission.%s" % (RED, geoDbCountry, END))

    if errors:
        exit(1)


    #Main options
    print("Reading command line arguments...")
    parser = argparse.ArgumentParser(usage=usage_stm)
    parser.add_argument("-i", "--inputFile", dest="inputFile")
    parser.add_argument("-m", "--mac", dest="macAddr", default="")
    parser.add_argument("-d", "--device", dest="device", default="")
    parser.add_argument("-c", "--deviceList", dest="deviceList", default=destDir+"/aux/devices_uk.txt")
    parser.add_argument("-a", "--ip", dest="ipAddr")
    parser.add_argument("-f", "--figDir", dest="figDir", default=destDir+"/figures")
    parser.add_argument("-t", "--noTimeShift", dest="noTimeShift", action="store_true", default=False)
    parser.add_argument("-s", "--hostsFile", dest="hostsFile")
    parser.add_argument("-b", "--lab", dest="lab", default="")
    parser.add_argument("-e", "--experiment", dest="experiment", default="")
    parser.add_argument("-n", "--network", dest="network", default="")
    parser.add_argument("-o", "--outputFile", dest="outputFile", default=destDir+"/experiment.csv")
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
        print("%sError: Pcap input file required.%s" % (RED, END))
        done = True
    elif not options.inputFile.endswith(".pcap"):
        print("%sError: Pcap input file required. Received \"%s\"%s" % (RED, options.inputFile, END))
        done = True
    elif not os.path.isfile(options.inputFile):
        print("%sError: The input file \"%s\" does not exist.%s" % (RED, options.inputFile, END))
        done = True

    if options.hostsFile == "":
        options.hostsFile = options.inputFile

    if not options.outputFile.endswith(".csv"):
        print("%sError: The output file should be a .csv file. Received \"%s\".%s" % (RED, options.outputFile, END))
        done = True

    noMACDevice = False
    validDeviceList = True
    if options.macAddr == "" and options.device == "":
        print("%sError: Either the MAC address (-m) or device (-d) must be specified.%s" % (RED, END))
        done = True
        noMACDevice = True
    else:
        if options.macAddr == "":
            if not options.deviceList.endswith(".txt"):
                print("%sError: Device list must be a text file (.txt). Received \"%s\"%s" % (RED, options.deviceList, END))
                done = True
                validDeviceList = False
            elif not os.path.isfile(options.deviceList):
                print("%sError: Device list file \"%s\" does not exist.%s" % (RED, options.deviceList, END))
                done = True
                validDeviceList = False
        else:
            options.macAddr = options.macAddr.lower()
            if not re.match("([0-9a-f]{2}[:]){5}[0-9a-f]{2}$", options.macAddr):
                print("%sError: Invalid MAC address \"%s\". Valid format: dd:dd:dd:dd:dd:dd%s" % (RED, options.macAddr, END))
                done = True

    if validDeviceList:
        devices = Device.Devices(options.deviceList)
        if options.macAddr == "" and not noMACDevice:
            if not devices.deviceInList(options.device):
                print("%sError: The device \"%s\" does not exist in the device list in \"%s\".%s" % (RED, options.device, options.deviceList, END))
                done = True
            else:
                options.macAddr = devices.getDeviceMac(options.device)

    plotTypes = ["StackPlot", "LinePlot", "ScatterPlot", "BarPlot", "PiePlot", "BarHPlot"]
    ipLocTypes = ["", "Country", "Host", "TSharkHost", "RipeCountry", "IP"]
    ipAttrTypes = ["", "addrPacketSize", "addrPacketNum"]
    for graph in graphs:
        if graph.plot not in plotTypes:
            print("%sError: \"%s\" is not a valid plot type. Must be either \"StackPlot\", \"LinePlot\", \"ScatterPlot\", \"BarPlot\", \"PiePlot\", or \"BarHPlot\".%s" % (RED, graph.plot, END))
            done = True
        else:
            if graph.protocol == "":
                print("%sError: A protocol (-p) must be specified for \"%s\".%s" % (RED, graph.plot, END))
                done = True
            if graph.ipLoc not in ipLocTypes:
                print("%sError: Invalid IP locator method \"%s\" for \"%s\". Must be either \"Country\", \"Host\", \"TSharkHost\", \"RipeCountry\", or \"IP\".%s" % (RED, graph.ipLoc, graph.plot, END))
                done = True
            if graph.ipAttr not in ipAttrTypes:
                print("%sError: Invalid IP Attribute \"%s\" for \"%s\". Must be either \"addrPacketSize\" or \"addrPacketNum\".%s" % (RED, graph.ipAttr, graph.plot, END))
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
    ipMap.loadOrgMapping(destDir + "/aux/ipToOrg.csv")
    ipMap.loadCountryMapping(destDir + "/aux/ipToCountry.csv")

    Utils.sysUsage("TShark hosts loaded")

    print("Generating output CSV...")
    de = DataPresentation.DomainExport(nodeStats.stats.stats, ipMap, options, geoDbCity, geoDbCountry)
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
        pm = DataPresentation.PlotManager(nodeStats.stats.stats, graphs, options, geoDbCity, geoDbCountry)
        pm.ipMap = ipMap
        pm.generatePlot()

        Utils.sysUsage("Plots generated")

    print("\nDestintaion analysis finished.")
    sys.exit()
