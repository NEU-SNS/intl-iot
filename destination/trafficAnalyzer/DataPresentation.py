import os
import csv

import matplotlib.pyplot as plt
import numpy as np

from . import Stats, IP, Constants


class PlotManager(object):
    def __init__(self, stats, graphs):
        self.graphs = graphs
        self.subPlotCounter = 1
        self.stats = stats

    def showGraphs(self):
        for graph in self.graphs:
            print(graph)

    def generatePlot(self, pcap_file, fig_dir, geo_db_city, geo_db_country):
        plt.figure(figsize=(15, 15))
        plt.title(pcap_file)

        for plot in self.graphs:
            plt.subplot(len(self.graphs), 1, self.subPlotCounter)
            if plot["plt"] == "stackplot":
                plt.xlabel("Packet TS (sec)")
                plt.ylabel("Total Packet Size (bytes)")
                self.generateStackPlot(plot)
            elif plot["plt"] in ["lineplot", "scatterplot", "barplot"]:
                plt.xlabel("Packet TS (sec)")
                plt.ylabel("Packet Size (bytes)")
                class_name = ""
                if plot["plt"] == "lineplot":
                    class_name = "LinePlot"
                elif plot["plt"] == "scatterplot":
                    class_name = "ScatterPlot"
                elif plot["plt"] == "barhplot":
                    class_name == "BarHPlot"

                self.generateLinePlot(plot, class_name)
            elif plot["plt"] in ["pieplot", "barhplot"]:
                if plot["ip_attr"] == "" or plot["ip_attr"] == "addrpcktsize":
                    plt.xlabel("Packet Size (bytes)")
                else:
                    plt.xlabel("Number Packets")
                plt.ylabel("IP Address")
                class_name = ""
                if plot["plt"] == "pieplot":
                    class_name = "PiePlot"
                elif plot["plt"] == "barhplot":
                    class_name = "BarHPlot"

                self.generatePiePlot(plot, class_name, geo_db_city, geo_db_country)

            self.subPlotCounter += 1 
   
        if not os.path.isdir(fig_dir):
            os.system('mkdir -pv %s' % fig_dir)

        graph_path = os.path.join(fig_dir, self.sanitiseFileName(pcap_file))
        plt.savefig(graph_path)
        print("Plot successfully saved to \"%s\"" % graph_path)
        #plt.show()

    def generateStackPlot(self, options):
        self.sp = StackPlot(self.stats, plt)
        for protocol in [options["prot_snd"], options["prot_rcv"]]:
            self.sp.addDataToStack(protocol, "packetSize", protocol)

        self.sp.plotFig()

    def generateLinePlot(self, options, class_name):
        self.lp = globals()[class_name](self.stats, plt)
        for protocol in [options["prot_snd"], options["prot_rcv"]]:
            self.lp.addLine(protocol, "packetTS", "packetSize", protocol)

        self.lp.plotFig()

    def generatePiePlot(self, options, class_name, geo_db_city, geo_db_country):
        self.pp = globals()[class_name](self.stats, plt, self.ipMap, geo_db_city, geo_db_country, class_name)
        for protocol in [options["prot_snd"], options["prot_rcv"]]:
            self.pp.splitIPBy(protocol, options["ip_loc"], options["ip_attr"])
 
        self.pp.plotFig()

    def sanitiseFileName(self, file_name):
        keepcharacters = ('-', '.', '_')
        plots = "".join("_" + plot["plt"] for plot in self.graphs)
        return "".join(c for c in file_name[:-5] if c.isalnum() or c in keepcharacters).rstrip()\
               + plots + ".png"


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
    def normaliseData(self, data):
        keys = self.getKeysFromDict(data) 

        for layer, domains in data.items():
            for key in keys:
                if key not in domains:
                    data[layer][key] = 0

    '''
    Function extract a set of unique keys from the second level of a
    two-level dictionary.

    Args:
        data (dict): Two-level dictionary (a dictionary of dictionaries)

    Returns:
        keys (set): A set of unique keys from the second level of a two-level
                    dictionary.
    '''
    def getKeysFromDict(self, data):
        return set([item for sublist in [list(dict.keys(v)) for k, v in data.items()]
                    for item in sublist])


class StackPlot(DataPresentation):
    def __init__(self, stats, plot):
        super().__init__(stats, plot) 

    def addDataToStack(self, layer, y_field, label, x_field = "packetTS"):
        self.labels.append(label)
        try:
            xData = getattr(self.stats[layer], x_field)
            yData = getattr(self.stats[layer], y_field)
            if len(self.x) == 0:
                self.x = xData
                self.y.append(yData)
                return

            self.x, self.y = self.sm.mergeStats(self.x, xData, self.y, yData)
        except KeyError:
            print("StackPlot: There is no traffic for protocol {}.".format(y_field))
            return 

    def plotFig(self, cum_sum=True):
        if cum_sum:
            self.y = self.sm.cumSumList(self.y)
    
        self.plot.stackplot(self.x, *self.y, labels=self.labels)
        self.plot.legend(loc='upper left')


class LinePlot(DataPresentation):
    def __init__(self, stats, plot):
        super().__init__(stats, plot)

    def addLine(self, layer, x_field, y_field, label):
        self.labels.append(label)
        try: 
            self.x.append(getattr(self.stats[layer], x_field))
            self.y.append(getattr(self.stats[layer], y_field))
        except KeyError:
            print("LinePlot: There is no traffic for protocol {}.".format(layer))

    def mergeData(self, merge_val):
        for i, x in enumerate(self.x):
            self.x[i] = self.sm.reduceValues(x, merge_val)
    
        for i, y in enumerate(self.y):
            self.y[i] = self.sm.mergeValues(y, merge_val)

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
    def __init__(self, stats, plot, ipMapping, geoDbCity, geoDbCountry, class_name):
        super().__init__(stats, plot)
        self.ipResolver = IP.IPResolver(ipMapping, geoDbCity, geoDbCountry)
        self.class_name = class_name

    def splitIPBy(self, layer, method, field="addrpcktsize", reset=False):
        if reset:
            self.dataDict = {}

        try:
            if method == "" or method is None:
                method = "ip"

            if field == "" or field is None:
                field = "addrpcktsize"
            
            ip_dict = getattr(self.stats[layer], field)
            #print(layer, field, ip_dict)
            self.dataDict[layer] = {}
            self.ipResolver.splitIPBy(ip_dict, method, self.dataDict[layer])
        except KeyError:
            print("  %s: There is no traffic for protocol \"%s\"." % (self.class_name, layer))

    def plotFig(self):
        self.plot.pie(list(self.dataDict.values()), labels=list(dict.keys(self.dataDict)),
                      autopct='%1.1f%%')


class BarHPlot(PiePlot):
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
    def plotFig(self):
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

    def analyzeFreq(self, layer, y_field):
        data = getattr(self.stats[layer], y_field)

        self.fft = np.fft.fft(data)
        self.freq = np.fft.fftfreq(len(data))
   
    def plotFig(self):
        self.plot.plot(self.freq, self.fft.real, self.freq, self.fft.imag)


class DomainExport(DataPresentation):
    def __init__(self, stats, ipMapping, geoDbCity, geoDbCountry):
        self.fields = []
        self.fileName = ""
        self.layers = []
        self.dataRows = []
        self.ipResolver = IP.IPResolver(ipMapping, geoDbCity, geoDbCountry)
        self.domains = {'packetSize': {}, 'packetNum': {}}
        super().__init__(stats, None)

    def loadIPFor(self, layer):
        self.layers.append(layer)
        for direction in [Constants.Direction.SND, Constants.Direction.RCV]:
            key = "{}-{}".format(layer, direction)
            try:
                self.domains['packetSize'][key] = self.stats[key].addrpcktsize
                self.domains['packetNum'][key] = self.stats[key].addrpcktnum
            except KeyError:
                pass

    def loadDiffIPFor(self, layer):
        self.layers.append(layer)
    
        try:
            snd_ip = dict.keys(self.stats[layer+"-"+Constants.Direction.SND].addrpcktnum)
        except KeyError:
            snd_ip = []
        try:
            rcv_ip = dict.keys(self.stats[layer+"-"+Constants.Direction.RCV].addrpcktnum)
        except KeyError:
            rcv_ip = []

        diff_ip = list(set(snd_ip) - set(rcv_ip))
        #print("Diff IP", diff_ip, snd_ip, rcv_ip)

        for ip in diff_ip:
            key = "{}-snd".format(layer)
            if key not in self.domains['packetSize']:
                self.domains['packetSize'][key] = {}
                self.domains['packetNum'][key] = {}
            try:
                self.domains['packetSize'][key][ip] = self.stats[key].addrpcktsize[ip]
                self.domains['packetNum'][key][ip] = self.stats[key].addrpcktnum[ip]
            except KeyError:
                pass

    def loadDomains(self, device, lab, experiment, network, pcap_file, baseTS):
        ips = self.getKeysFromDict(self.domains['packetSize'])
        for ip in ips:
            if self.ipResolver.isIPAddr(ip):
                domain_full = self.ipResolver.getDataPoint(ip, "TSharkHost", False)
                domain = self.ipResolver.extractDomain(domain_full)
                country = self.ipResolver.getDataPoint(ip, "CountryMapping", True, False)
                if country is None:
                    country = "XX"
                org = str(self.ipResolver.getDataPoint(ip, "OrgMapping", True, False))
            else: 
                domain_full = ip
                domain = ip
                country = "XX"
                org = "N/A"

            row = []
            row.append(baseTS)
            row.append(device)
            row.append(ip)
            row.append(domain)
            row.append(domain_full)
      
            for valueType in ["packetSize", "packetNum"]: 
                for layer in self.layers:
                    for direction in [Constants.Direction.SND, Constants.Direction.RCV]:
                        key = "{}-{}".format(layer, direction)
                        try: 
                            row.append(str(self.getVal(self.domains[valueType][key], ip)))
                        except KeyError:
                            row.append("0")

            row.append(country)
            row.append("0")
            row.append(lab)
            row.append(experiment)
            row.append(network)
            row.append(pcap_file)
            row.append(org)

            self.dataRows.append(row)

    def exportDataRows(self, output_file):
        csv_data = "\n".join([",".join(r) for r in self.dataRows]) + "\n"
        with open(output_file, 'a') as f:
            f.write(csv_data)

    def getVal(self, _dict, key):
        if key in _dict:
            return _dict[key]
        return 0

    def create_csv(out_file):
        out_dirname = os.path.dirname(out_file)
        if out_dirname != "" and not os.path.isdir(out_dirname):
            os.system("mkdir -pv " + out_dirname)

        with open(out_file, 'w') as f:
            f.write("ts,device,ip,host,host_full,traffic_snd,traffic_rcv,packet_snd,"
                    "packet_rcv,country,party,lab,experiment,network,input_file,organization\n")

    def sort_csv(output_file):
        reader = csv.reader(open(output_file))
        header = next(reader)
        csv_data = ",".join(header) + "\n"
        sorted_list = sorted(reader)
        csv_data = csv_data + "\n".join([",".join(r) for r in sorted_list]) + "\n"
        with open(output_file, "w") as f:
            f.write(csv_data)

