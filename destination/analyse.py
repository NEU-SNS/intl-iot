""" Scripts processing pcap files and generating text output and figures """

import os
import sys
import pyshark

import numpy as np
import matplotlib.pyplot as plt
from scipy import signal

import re

from trafficAnalyser import *

from optparse import OptionParser, OptionGroup, OptionValueError

__author__ = "Roman Kolcun"
__copyright__ = "Copyright 2019"
__credits__ = ["Roman Kolcun"]
__license__ = "GPL"
__version__ = "2.0"
__maintainer__ = "Roman Kolcun"
__email__ = "roman.kolcun@imperial.ac.uk"
__status__ = "Development"

usage_stm = """
Usage: analyse.py [options] arg1 arg2

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -i INPUTFILE, --inputFile=INPUTFILE
                        Input File
  -m MACADDR, --mac=MACADDR
                        MAC Address of the device.
  -a IPADDR, --ip=IPADDR
                        IP Address of the device.
  -f FIGDIR, --figDir=FIGDIR
                        Directory to save figures.
  -t, --noTimeShift     Do not perform time shift.
  -s HOSTSFILE, --hostsFile=HOSTSFILE
                        File produced by tshark extracting hosts from the
                        pcacp file.
  -d DEVICE, --device=DEVICE
                        Device name.
  -b LAB, --lab=LAB     Lab name.
  -e EXPERIMENT, --experiment=EXPERIMENT
                        Experiment name.
  -n NETWORK, --network=NETWORK
                        Network name.
  -o OUTPUTFILE, --outputFile=OUTPUTFILE
                        Output CSV file.
  -c DEVICELIST, --deviceList=DEVICELIST
                        List containing all devices.
  --findDiff            Find domains which do not reply.

  Graph Options:
    -g PLOT, --graph=PLOT
                        Type of graph.
    -l IPLOC, --ipLoc=IPLOC
                        How IP should be translated to a location or a domain
                        name
    -p PROTOCOL, --protocol=PROTOCOL
                        Which protocols should be analysed
    -r IPATTR, --ipAttr=IPATTR
                        When showing domains/IPs/countries should the number
                        of packet or overall traffic be shown
"""

def print_usage():
    print(usage_stm)
    exit()

class GraphDesc(object):
  def __init__(self):
    self.graphs = []
    usage = "usage:"
    self.parser = OptionParser(usage) 
    self.addOptions(self.parser)
  
  def addOptions(self, parser):
    parser.add_option("-l", "--ipLoc", dest="ipLoc", type="choice",
      choices=["Country", "Host", "TSharkHost", "RipeCountry", "IP"], default=None,
      help="How IP should be translated to a location or a domain name")
    parser.add_option("-p", "--protocol", dest="protocol",
      help="Which protocols should be analysed")
    parser.add_option("-r", "--ipAttr", dest="ipAttr", type="choice",
      choices=["addrPacketSize", "addrPacketNum"], default=None,
      help="When showing domains/IPs/countries should the number of packet or overall traffic be shown")

  def parseGraphOptions(self, option, optStr, value, parser):
    plotTypes = ["StackPlot", "LinePlot", "ScatterPlot", "BarPlot", "PiePlot", "BarHPlot"]
    if value not in plotTypes:
      raise OptionValueError("Allowed graph types: {}".format(plotTypes))

    parser.values.plot = value
    try:
      nextIndex = parser.rargs.index(optStr)
    except ValueError:
      nextIndex = len(parser.rargs)

    args = parser.rargs[:nextIndex]

    del parser.rargs[:len(args)]

    (options, _args) = self.parser.parse_args(args)
    options.plot = value
    self.graphs.append(options)

  def normaliseMac(self, option, optStr, value, parser):
    if value != "":
      value = Device.Device.normaliseMac(value)
    setattr(parser.values, option.dest, value)

if __name__ == "__main__":
  gd = GraphDesc()

  #Add options to usage statement
  usage = "usage: %prog [options] arg1 arg2"
  parser = OptionParser(usage, version="%prog 0.1")
  parser.add_option("-i", "--inputFile", dest="inputFile", help="Input File")
  parser.add_option("-m", "--mac", dest="macAddr", action="callback", type="string", default="", 
      callback=gd.normaliseMac, help="MAC Address of the device.")
  parser.add_option("-a", "--ip", dest="ipAddr", help="IP Address of the device.")
  parser.add_option("-f", "--figDir", dest="figDir", default="figures", 
      help="Directory to save figures.")
  parser.add_option("-t", "--noTimeShift", dest="noTimeShift", action="store_true", 
      default=False, help="Do not perform time shift.")
  parser.add_option("-s", "--hostsFile", dest="hostsFile", 
      help="File produced by tshark extracting hosts from the pcacp file.")
  parser.add_option("-d", "--device", dest="device", default="", 
      help="Device name.")
  parser.add_option("-b", "--lab", dest="lab", default="", 
      help="Lab name.")
  parser.add_option("-e", "--experiment", dest="experiment", default="", 
      help="Experiment name.")
  parser.add_option("-n", "--network", dest="network", default="", 
      help="Network name.")
  parser.add_option("-o", "--outputFile", dest="outputFile", default="experiment.csv",
      help="Output CSV file.")
  parser.add_option("-c", "--deviceList", dest="deviceList", default="aux/devices_uk.txt",
      help="List containing all devices.")
  parser.add_option("--findDiff", dest="findDiff", action="store_true", default=False,
      help="Find domains which do not reply.")

  #Add options to graph
  graphParser = OptionGroup(parser, "Graph Options")
  
  graphParser.add_option("-g", "--graph", dest="plot", action="callback",
      type="string", callback=gd.parseGraphOptions,
      help="Type of graph.")
  gd.addOptions(graphParser)
  
  parser.add_option_group(graphParser)

  (options, args) = parser.parse_args() #Parse arguments
  
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

  if done:
      print_usage()

  cap = pyshark.FileCapture(options.inputFile, use_json = True)
  Utils.sysUsage("PCAP file loading")
  
  try:
    if options.noTimeShift:
      baseTS = 0
      cap[0]
    else:
      baseTS = float(cap[0].frame_info.time_epoch)
  except KeyError:
    print ("File {} does not contain any packets.".format(options.inputFile))
    sys.exit()

 
  nodeId = Node.NodeId(options.macAddr, options.ipAddr)
  nodeStats = Node.NodeStats(nodeId, baseTS, devices, options)
  
  for packet in cap:
    nodeStats.processPacket(packet)
 
  Utils.sysUsage("Packets processed")
  #print (sorted(list(dict.keys(nodeStats.stats.stats))))
  
  
  ipMap = IP.IPMapping()
  ipMap.extractFromFile(options.inputFile)
  ipMap.loadOrgMapping("aux/ipToOrg.csv")
  ipMap.loadCountryMapping("aux/ipToCountry.csv")

  Utils.sysUsage("TShark hosts loaded")
  
  de = DataPresentation.DomainExport(nodeStats.stats.stats, ipMap, options)
  if options.findDiff:
    de.loadDiffIPFor("eth")
  else:
    de.loadIPFor("eth")
  de.loadDomains()
  de.exportDataRows(options.outputFile)
  #sys.exit()

  Utils.sysUsage("Data exported")

  pm = DataPresentation.PlotManager(nodeStats.stats.stats, gd, options)
  pm.ipMap = ipMap
  pm.generatePlot()
  
  Utils.sysUsage("Plots generated")

  sys.exit()
  
