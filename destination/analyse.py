""" Scripts processing pcap files and generating text output and figures """


import sys
import pyshark

import numpy as np
import matplotlib.pyplot as plt
from scipy import signal

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



  graphParser = OptionGroup(parser, "Graph Options")

  graphParser.add_option("-g", "--graph", dest="plot", action="callback",
      type="string", callback=gd.parseGraphOptions,
      help="Type of graph.")
  gd.addOptions(graphParser)
  
  parser.add_option_group(graphParser)

  (options, args) = parser.parse_args()
  if options.hostsFile == "":
    options.hostsFile = options.inputFile
  
  devices = Device.Devices(options.deviceList)
 
  if options.macAddr == "":
    options.macAddr = devices.getDeviceMac(options.device)
  
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
  ipMap.extractFromFile(options.hostsFile)
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
  
