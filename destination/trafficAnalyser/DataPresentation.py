import numpy as np
import matplotlib.pyplot as plt
import os

from . import Stats, IP, Constants

class PlotManager(object):
    def __init__(self, stats, graphs, options):
        self.graphs = graphs
        self.subPlotCounter = 1
        self.stats = stats
        self.options = options

    def showGraphs(self):
        for graph in self.graphs:
            print(graph)

    def generatePlot(self):
        plt.figure(figsize=(15, 15))
        plt.title(self.options.inputFile)

        for plot in self.graphs:
            plt.subplot(len(self.graphs), 1, self.subPlotCounter)
            if plot.plot == "StackPlot":
                plt.xlabel("Packet TS")
                plt.ylabel("Packet Size")
                self.generateStackPlot(plot)
            elif plot.plot in ["LinePlot", "ScatterPlot", "BarPlot"]:
                plt.xlabel("Packet TS")
                plt.ylabel("Packet Size")
                self.generateLinePlot(plot, plot.plot)
            elif plot.plot in ["PiePlot", "BarHPlot"]:
                if self.options.ipAttr == None or self.options.ipAttr == "addrPacketSize":
                    plt.xlabel("Packet Size")
                else:
                    plt.xlabel("Number Packets")
                plt.ylabel("IP Address")
                self.generatePiePlot(plot, plot.plot)

            self.subPlotCounter += 1 
   
        if not os.path.isdir(self.options.figDir):
            os.system('mkdir -pv %s' % self.options.figDir)
        graphPath = os.path.join(self.options.figDir,
            self.sanitiseFileName(self.options.inputFile, self.graphs))
        plt.savefig(graphPath)
        print("Plot successfully saved to \"%s\"" % graphPath)
        #plt.show()

    def generateStackPlot(self, options):
        self.sp = StackPlot(self.stats, plt)
        for protocol in options.protocol.split(','):
            self.sp.addDataToStack(protocol, "packetSize", protocol)

        self.sp.plotFig()

    def generateLinePlot(self, options, className):
        self.lp = globals()[className](self.stats, plt)
        for protocol in options.protocol.split(','):
            self.lp.addLine(protocol, "packetTS", "packetSize", protocol)

        self.lp.plotFig()

    def generatePiePlot(self, options, className):
        self.pp = globals()[className](self.stats, plt, self.ipMap)
        for protocol in options.protocol.split(','):
            self.pp.splitIPBy(protocol, options.ipLoc, options.ipAttr)
 
        self.pp.plotFig()

    def sanitiseFileName(self, fileName, graphs):
        keepcharacters = ('-','.','_')
        plots = "".join("_" + plot.plot for plot in graphs)
        return "".join(c for c in fileName if c.isalnum() or c in keepcharacters).rstrip()+plots+".png"

class DataPresentation(object):
    def __init__(self, stats, plot):
        self.stats = stats
        self.plot = plot
    
        self.sm = Stats.StatsMerge()
        self.x = []
        self.y = []
        self.labels = []
        self.data = []
        self.dataDict = {}

    def normaliseData(self, data):
        '''
        Each dictionary in data may have different keys. In order to plot them it
        is needed to normalise them, i.e. each dictionary has exactly the same
        keys. The default value for all the keys that were not present in the
        dictionary is zero.

        Args:
            data (dict): For each layer it holds a dictionary with domain names and
                        a value (either the number of packets or the amount of
                        traffic). Usually self.dataDict is passed as an argument.
      
        '''
        keys = self.getKeysFromDict(data) 

        for layer, domains in data.items():
            for key in keys:
                if key not in domains:
                    data[layer][key] = 0

    def getKeysFromDict(self, data):
        '''
        Function extract a set of unique keys from the second level of a
        two-level dictionary.

        Args:
            data (dict): Two-level dictionary (a dictionary of dictionaries)

        Returns:
            keys (set): A set of unique keys from the second level of a two-level
                        dictionary.
        '''
        return set([item for sublist in [list(dict.keys(v)) for k, v in data.items()] for item in sublist])

class StackPlot(DataPresentation):
    def __init__(self, stats, plot):
        super().__init__(stats, plot) 

    def addDataToStack(self, layer, yField, label, xField = "packetTS"):
        self.labels.append(label)
        try:
            xData = getattr(self.stats[layer], xField)
            yData = getattr(self.stats[layer], yField)
            if len(self.x) == 0:
                self.x = xData
                self.y.append(yData)
                return

            self.x, self.y = self.sm.mergeStats(self.x, xData, self.y, yData)
        except KeyError as err:
            print ("StackPlot: There is no traffic for protocol {}.".format(yField))
            return 

    def plotFig(self, cumSum = True):
        if cumSum:
            self.y = self.sm.cumSumList(self.y)
    
        self.plot.stackplot(self.x, *self.y, labels = self.labels)
        self.plot.legend(loc='upper left')

class LinePlot(DataPresentation):
    def __init__(self, stats, plot):
        super().__init__(stats, plot)

    def addLine(self, layer, xField, yField, label):
        self.labels.append(label)
        try: 
            self.x.append(getattr(self.stats[layer], xField))
            self.y.append(getattr(self.stats[layer], yField))
        except KeyError as err:
            print ("LinePlot: There is no traffic for protocol {}.".format(layer))

    def mergeData(self, mergeVal):
        for i, x in enumerate(self.x):
            self.x[i] = self.sm.reduceValues(x, mergeVal)
    
        for i, y in enumerate(self.y):
            self.y[i] = self.sm.mergeValues(y, mergeVal)

    def cumSum(self):
        self.y = self.sm.cumSumList(self.y)

    def plotFig(self):
        for i, _ in enumerate(self.x):
            self.plot.plot(self.x[i], self.y[i], label=self.labels[i])

        self.plot.legend()

class ScatterPlot(LinePlot):
    def plotFig(self):
        for i, _ in enumerate(self.x):
            self.plot.scatter(self.x[i], self.y[i], s=1, label=self.labels[i])

        self.plot.legend()

class BarPlot(LinePlot):
    def plotFig(self):
        for i, _ in enumerate(self.x):
            self.plot.bar(self.x[i], self.y[i])

class PiePlot(DataPresentation):
    def __init__(self, stats, plot, ipMapping):
        super().__init__(stats, plot)
        self.ipResolver = IP.IPResolver(ipMapping)

    def splitIPBy(self, layer, method, field = "addrPacketSize", reset = False):
        if reset:
            self.dataDict = {}

        try:
            if field == None:
                field = "addrPacketSize"
            ipDict = getattr(self.stats[layer], field)
            #print(layer, field, ipDict)
            self.dataDict[layer] = {}
            self.ipResolver.splitIPBy(ipDict, method, self.dataDict[layer])
        except KeyError as err:
            print("{}: There is no traffic for protocol {}".format(__class__, layer))

    def plotFig(self):
        print(self.dataDict)
        print(list(self.dataDict.values())[0].values())
        print(self.dataDict.values())
        print("\n")
        print(len(list(dict.keys(self.dataDict))))
        print(len(list(list(self.dataDict.values())[0].values())))
        print(len(list(list(self.dataDict.values())[1].values())))
        self.plot.pie(list(self.dataDict.values()), labels=list(dict.keys(self.dataDict)), autopct='%1.1f%%')

class BarHPlot(PiePlot):
    def plotFig(self):
        '''
        Plots the figure. Because the plot is stacked it is necessary to define
        where the next set of bars have to start.  For this purpose the "left"
        variable stores at which position the next bar should start.  First all
        data need to be normalised. After this operation each dictionary contains
        the same set of keys.

        Variables: 
            left (list): It is the same length as the number of entries in each
                         dictionary. After the current layer is processed it sums the
                         values from the current layer with the already processed
                         values.

            keys (list): Sorted list of unique keys from each dictionary. They have
                         to be sorted so they are in the same order for each layer.

            vals (list): Values associated with the keys.
        '''
        plots = []
        labels = []
        self.normaliseData(self.dataDict)
        left = [0]*len(self.dataDict[list(dict.keys(self.dataDict))[0]])
    
        for layer, data in self.dataDict.items():
            keys, vals = list(zip(*sorted(data.items())))
            #print(keys, vals, left)
            plots.append(self.plot.barh(keys, vals, left=left))
            left = [l1 + l2 for l1, l2 in zip(left, list(vals))]
            labels.append(layer)

    
        self.plot.legend(plots, labels)

class FreqPlot(DataPresentation):
    def __init__(self, stats, plot):
        self.fft = None
        self.freq = None
        super().__init__(stats, plot)

    def analyseFreq(self, layer, yField):
        data = getattr(self.stats[layer], yField)

        self.fft = np.fft.fft(data)
        self.freq = np.fft.fftfreq(len(data))
   
    def plotFig(self):
        self.plot.plot(self.freq, self.fft.real, self.freq, self.fft.imag)

class DomainExport(DataPresentation):
    def __init__(self, stats, ipMapping, options):
        self.fields = []
        self.fileName = ""
        self.layers = []
        self.dataRows = []
        self.ipResolver = IP.IPResolver(ipMapping)
        self.domains = {'packetSize': {}, 'packetNum': {}}
        self.options = options
        super().__init__(stats, None)

    def loadIPFor(self, layer):
        self.layers.append(layer)
        for direction in [Constants.Direction.SND, Constants.Direction.RCV]:
            key = "{}-{}".format(layer, direction)
            try:
                self.domains['packetSize'][key] = self.stats[key].addrPacketSize
                self.domains['packetNum'][key] = self.stats[key].addrPacketNum
            except KeyError:
                pass

    def loadDiffIPFor(self, layer):
        self.layers.append(layer)
    
        try:
            sndIP = dict.keys(self.stats[layer+"-"+Constants.Direction.SND].addrPacketNum)
        except KeyError:
            sndIP = []
        try:
            rcvIP = dict.keys(self.stats[layer+"-"+Constants.Direction.RCV].addrPacketNum)
        except KeyError:
            rcvIP = []

        diffIP = list(set(sndIP) - set(rcvIP))
        #print ("Diff IP", diffIP, sndIP, rcvIP)

        for ip in diffIP:
            key = "{}-snd".format(layer)
            if key not in self.domains['packetSize']:
                self.domains['packetSize'][key] = {}
                self.domains['packetNum'][key] = {}
            try:
                self.domains['packetSize'][key][ip] = self.stats[key].addrPacketSize[ip]
                self.domains['packetNum'][key][ip] = self.stats[key].addrPacketNum[ip]
            except KeyError:
                pass

    def loadDomains(self):
        ips = self.getKeysFromDict(self.domains['packetSize'])
        rows = []
        for ip in ips:
            if self.ipResolver.isIPAddr(ip): 
                domainFull = self.ipResolver.getDataPoint(ip, "TSharkHost", False)
                domain = self.ipResolver.extractDomain(domainFull)
                country = self.ipResolver.getDataPoint(ip, "CountryMapping", True, False)
                if country is None:
                    country = "XX"
                org = str(self.ipResolver.getDataPoint(ip, "OrgMapping", True, False))
            else: 
                domainFull = ip
                domain = ip
                country = "XX"
                org = "N/A"

            row = []
            row.append(self.options.device)
            row.append(ip)
            row.append(domain)
            row.append(domainFull)
      
            for valueType in ["packetSize", "packetNum"]: 
                for layer in self.layers:
                    for direction in [Constants.Direction.SND, Constants.Direction.RCV]:
                        key = key = "{}-{}".format(layer, direction)
                        try: 
                            row.append(str(self.getVal(self.domains[valueType][key], ip)))
                        except KeyError:
                            row.append("0")

            row.append(country)
            row.append("0")
            row.append(self.options.lab)
            row.append(self.options.experiment)
            row.append(self.options.network)
            row.append(self.options.inputFile)
            row.append(org)

            self.dataRows.append(row)

    def exportDataRows(self):
        if not os.path.isfile(self.options.outputFile):
            saveStr = "device,ip,host,host_full,traffic_snd,traffic_rcv,packet_snd,packet_rcv,country,party,lab,experiment,network,input_file,organisation\n"
        else:
            saveStr = ""
   
        saveStr+= "\n".join([",".join(r) for r in self.dataRows])+"\n"
    
        with open(self.options.outputFile, 'a+') as f:
            f.write(saveStr)

        print("Analyzed data from \"%s\" successfully written to \"%s\"" % (self.options.inputFile, self.options.outputFile))

    def getVal(self, _dict, key):
        if key in _dict:
            return _dict[key]
        return 0

