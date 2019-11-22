import numpy as np
import sys
from . import Constants

class Stats(object):

  def __init__(self, node):
    self.node = node
    self.stats = {}

  def getStats(self, layer, direction):
    key = "{}-{}".format(layer, direction)
    
    if key not in self.stats:
      self.stats[key] = StatsData(self.node, layer, direction)

    return self.stats[key]

  def printStats(self):
    for key, val in sorted(self.stats.items()):
      print("{}: {}".format(key, val))

class StatsData(object):
    
  def __init__(self, node, layerName, direction):
    self.node = node
    self.layerName = layerName
    self.direction = direction
    self.packets = []
    self.packetTS = []
    self.packetDiff = []
    self.packetSize = []
    self.addrPacketNum = {}
    self.addrPacketSize = {}
    self.srcPort = {}
    self.destPort = {}
    self.flags = []
    self.options = []

  def increaseCount(self, _dict, key, val = 1):
    if key not in _dict:
      _dict[key] = 0

    _dict[key] += val

  def processLayer(self, packet, layer):
    """ Currently it is not needed to store all packets """
    #self.packets.append(layer)
    time = float(packet.frame_info.time_epoch) - self.node.baseTS
    self.packetTS.append(time)
    try:
      self.packetDiff.append(time - self.packetTS[-2])
    except IndexError:
      self.packetDiff.append(0)
  
    length = self.getDataLength(layer)
    if length >= 0:
      self.packetSize.append(length)
    else:
      self.packetSize.append(packet.length)
    
    self.increaseCount(self.addrPacketNum, packet.addr.getAddr())
    self.increaseCount(self.addrPacketSize, packet.addr.getAddr(), packet.length)
    
    if self.layerHasPort(layer):
      self.increaseCount(self.srcPort, layer.srcport)
      self.increaseCount(self.destPort, layer.dstport)
    
    if 'flags' in layer.field_names:
      self.flags.append(layer.flags)
    if 'options' in layer.field_names:
      self.options.append(layer.options)

  def getOtherAddr(self, layer):
    try:
      if self.direction == Direction.SND:
        return layer.dst
      return layer.src
    except AttributeError:
      return ""
      
  def layerHasPort(self, layer):
    if layer.layer_name == Constants.Layer.TCP or layer.layer_name == Constants.Layer.UDP:
      return True
    return False

  def getDataLength(self, layer):
    intersect = list(set(layer.field_names) & set(['len', 'data_len', 'length']))
    if len(intersect) == 1:
      return int(getattr(layer, intersect[0]), 0)
    elif len(intersect) > 1:
      #print ("intersect:",intersect, layer.field_names, layer.layer_name)
      return int(getattr(layer, intersect[0]), 0)
    else:
      return -1

  def __str__(self):
    return "addr: {}".format(self.srcPort)

class StatsMerge(object):

  def __init__(self):
    pass

  def mergeStats(self, x1, x2, y1List, y2):
    x = []
    yDictList = []
    yList = [[] for i in range(len(y1List)+1)]

    for y1 in y1List:
      yDictList.append(dict(zip(x1, y1)))

    yDictList.append(dict(zip(x2, y2)))
    x = sorted(x1 + x2)
    
    for xVal in x:
      for i, yDict in enumerate(yDictList):
        if xVal in yDict:
          yList[i].append(yDict[xVal])
        else:
          yList[i].append(0)

    return x, yList

  def cumSumList(self, yList):
    yListNew = []
    
    for y in yList:
      yListNew.append(np.cumsum(y))
    
    return yListNew


  def mergeValues(self, valList, mergeVal):
    return np.add.reduceat(valList, np.arange(0, len(valList), mergeVal))

  def reduceValues(self, valList, reduceVal):
    return valList[::reduceVal]
