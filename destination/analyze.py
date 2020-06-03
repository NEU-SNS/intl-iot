""" Scripts processing pcap files and generating text output and figures """

import argparse
import os
import re
import sys
from multiprocessing import Process

import pyshark

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
PATH = sys.argv[0]
DEST_DIR = os.path.dirname(PATH)
if DEST_DIR == "":
    DEST_DIR = "."

TRAFFIC_ANA_DIR = DEST_DIR + "/trafficAnalyzer"
CONSTS = TRAFFIC_ANA_DIR + "/Constants.py"
DATA_PRES = TRAFFIC_ANA_DIR + "/DataPresentation.py"
DEV = TRAFFIC_ANA_DIR + "/Device.py"
DNS_TRACK = TRAFFIC_ANA_DIR + "/DNSTracker.py"
INIT = TRAFFIC_ANA_DIR + "/__init__.py"
IP = TRAFFIC_ANA_DIR + "/IP.py"
NODE = TRAFFIC_ANA_DIR + "/Node.py"
STAT = TRAFFIC_ANA_DIR + "/Stats.py"
UTIL = TRAFFIC_ANA_DIR + "/Utils.py"
GEO_DIR = DEST_DIR + "/geoipdb"
GEO_DB_CITY = GEO_DIR + "/GeoLite2-City.mmdb"
GEO_DB_COUNTRY = GEO_DIR + "/GeoLite2-Country.mmdb"
AUX_DIR = DEST_DIR + "/aux"
IP_TO_ORG = AUX_DIR + "/ipToOrg.csv"
IP_TO_COUNTRY = AUX_DIR + "/ipToCountry.csv"

SCRIPTS = [CONSTS, DATA_PRES, DEV, DNS_TRACK, INIT, IP, NODE, STAT, UTIL]

RED = "\033[31;1m"
END = "\033[0m"

#Check that traffic analyzer package has all files and correct permissions
errors = False
if not os.path.isdir(TRAFFIC_ANA_DIR):
    errors = True
    print("%s%s: Error: The \"%s/\" directory is missing.\n"
          "     Make sure it is in the same directory as %s.%s"
          % (RED, PATH, TRAFFIC_ANA_DIR, PATH, END), file=sys.stderr)
else:
    if not os.access(TRAFFIC_ANA_DIR, os.R_OK):
        errors = True
        print("%s%s: Error: The \"%s/\" directory does not have read permission.%s"
              % (RED, PATH, TRAFFIC_ANA_DIR, END), file=sys.stderr)
    if not os.access(TRAFFIC_ANA_DIR, os.X_OK):
        errors = True
        print("%s%s: Error: The \"%s/\" directory does not have execute permission.%s"
              % (RED, PATH, TRAFFIC_ANA_DIR, END), file=sys.stderr)
if errors:
    exit(1)

for f in SCRIPTS:
    if not os.path.isfile(f):
        errors = True
        print("%s%s: Error: The script \"%s\" cannot be found.\n"
              "     Please make sure it is in the same directory as \"%s\".%s"
              % (RED, PATH, f, PATH, END), file=sys.stderr)
    elif not os.access(f, os.R_OK):
        errors = True
        print("%s%s: Error: The script \"%s\" does not have read permission.%s"
              % (RED, PATH, f, END), file=sys.stderr)

if errors:
    exit(1)

from trafficAnalyzer import *
from trafficAnalyzer import Constants as c

args = [] #Main args
plots = [] #Graph args
devices = None


#isError is either 0 or 1
def print_usage(is_error):
    if is_error == 0:
        print(c.USAGE_STM)
    else:
        print(c.USAGE_STM, file=sys.stderr)

    exit(is_error)


def check_files(direc, files, is_geo):
    errors = False
    if not os.path.isdir(direc):
        errors = True
        print(c.MISSING % (direc, "directory"), file=sys.stderr)
    else:
        if not os.access(direc, os.R_OK):
            errors = True
            print(c.NO_PERM % ("directory", direc, "read"), file=sys.stderr)
        if not os.access(GEO_DIR, os.X_OK):
            errors = True
            print(c.NO_PERM % ("directory", direc, "execute"), file=sys.stderr)

    if not errors:
        missing_file = False
        for f in files:
            if not os.path.isfile(f):
                missing_file = errors = True
                print(c.MISSING % (f, "file"), file=sys.stderr)
            elif not os.access(f, os.R_OK):
                errors = True
                print(c.NO_PERM % ("file", f, "read"), file=sys.stderr)

        if missing_file and is_geo:
            print(c.DOWNLOAD_DB, file=sys.stderr)

    if errors:
        exit(1)


def main():
    global args, plots, devices

    [print_usage(0) for arg in sys.argv if arg in ["-h", "--help"]]

    print("Performing destination analysis...")
    print("Running %s..." % PATH)

    #Check that GeoLite2 databases and aux scripts exist and have proper permissions
    check_files(GEO_DIR, [GEO_DB_CITY, GEO_DB_COUNTRY], True)
    check_files(AUX_DIR, [IP_TO_ORG, IP_TO_COUNTRY], False)

    #Options
    parser = argparse.ArgumentParser(usage=c.USAGE_STM, add_help=False)
    parser.add_argument("-i", dest="in_dir", default="")
    parser.add_argument("-m", dest="mac_addr", default="")
    parser.add_argument("-d", dest="dev", default="")
    parser.add_argument("-c", dest="dev_list", default=DEST_DIR+"/aux/devices_uk.txt")
    parser.add_argument("-a", dest="ip_addr")
    parser.add_argument("-s", dest="hosts_file")
    parser.add_argument("-b", dest="lab", default="")
    parser.add_argument("-e", dest="experiment", default="")
    parser.add_argument("-w", dest="network", default="")
    parser.add_argument("-t", dest="no_time_shift", action="store_true", default=False)
    parser.add_argument("-y", dest="find_diff", action="store_true", default=False)
    parser.add_argument("-f", dest="fig_dir", default=DEST_DIR+"/figures")
    parser.add_argument("-o", dest="out_file", default=DEST_DIR+"/results.csv")
    parser.add_argument("-n", dest="num_proc", default="1")
    parser.add_argument("-g", dest="plots")
    parser.add_argument("-p", dest="protocols", default="")
    parser.add_argument("-l", dest="ip_locs", default="")
    parser.add_argument("-r", dest="ip_attrs", default="")
    parser.add_argument("-h", dest="help", action="store_true", default=False)

    #Parse Arguments
    args = parser.parse_args()

    if args.plots is not None:
        for val in args.plots.split(","):
            plot = {"plt": val.strip().lower()}
            plots.append(plot)

    headings = ["prot", "ip_loc", "ip_attr"]
    plot_len = len(plots)
    for header, attrs in zip(headings, [args.protocols, args.ip_locs, args.ip_attrs]):
        vals = [val.strip().lower() for val in attrs.split(",")]
        if len(vals) < plot_len:
            vals.extend([""] * (plot_len - len(vals)))

        for plt, val in zip(plots, vals):
            plt[header] = val
        
    for plt in plots:
        if "pieplot" == plt["plt"]:
            print(c.PIE_STM, file=sys.stderr)
            exit(1)

        if "ripecountry" == plt["ip_loc"]:
            print(c.RP_STM, file=sys.stderr)
            exit(1)

    if args.mac_addr != "":
        args.mac_addr = Device.Device.normaliseMac(args.mac_addr)

    #Error checking command line args
    errors = False
    if args.in_dir == "":
        errors = True 
        print(c.NO_IN_DIR, file=sys.stderr)
    elif not os.path.isdir(args.in_dir):
        errors = True
        print(c.INVAL % ("Input pcap directory", args.in_dir, "directory"), file=sys.stderr)
    else:
        if not os.access(args.in_dir, os.R_OK):
            errors = True
            print(c.NO_PERM % ("directory", option.in_dir, "read"), file=sys.stderr)
        if not os.access(args.in_dir, os.X_OK):
            errors = True
            print(c.NO_PERM % ("directory", args.in_dir, "execute"), file=sys.stderr)

    #if args.hosts_file == "":
    #    args.hosts_file = args.inputFile

    if not args.out_file.endswith(".csv"):
        errors = True
        print(c.WRONG_EXT % ("Output file", "CSV (.csv)", args.out_file), file=sys.stderr)

    no_mac_device = False
    valid_device_list = True
    if args.mac_addr == "" and args.dev == "":
        no_mac_devce = errors = True
        print(c.NO_MAC, file=sys.stderr)
    elif args.mac_addr == "":
        if not args.dev_list.endswith(".txt"):
            errors = True
            print(c.WRONG_EXT % ("Device list", "text (.txt)", args.dev_list), file=sys.stderr)
            valid_device_list = False
        elif not os.path.isfile(args.dev_list):
            errors = True
            print(c.INVAL % ("Device list file", args.dev_list, "file"), file=sys.stderr)
            valid_device_list = False
    else:
        args.mac_addr = args.mac_addr.lower()
        if not re.match("([0-9a-f]{2}[:]){5}[0-9a-f]{2}$", args.mac_addr):
            errors = True
            print(c.INVAL_MAC % args.mac_addr, file=sys.stderr)

    if valid_device_list:
        devices = Device.Devices(args.dev_list)
        if args.mac_addr == "" and not no_mac_device:
            if not devices.deviceInList(args.dev):
                errors = True
                print(c.NO_DEV % (args.dev, args.dev_list), file=sys.stderr)
            else:
                args.mac_addr = devices.getDeviceMac(args.dev)

    bad_proc = True
    num_proc = 1
    try:
        if int(args.num_proc) > 0:
            bad_proc = False
            num_proc = int(args.num_proc)
    except ValueError:
        pass

    if bad_proc:
        errors = True
        print(c.NON_POS % args.num_proc, file=sys.stderr)

    plot_types = ["stackplot", "lineplot", "scatterplot", "barplot", "pieplot", "barhplot"]
    ip_loc_types = ["country", "host", "tsharkhost", "ripecountry", "ip"]
    ip_attr_types = ["addrpcktsize", "addrpcktnum"]
    for plt in plots:
        if plt["ip_loc"] == "":
            plt["ip_loc"] = "ip"

        if plt["ip_attr"] == "":
            plt["ip_attr"] = "addrpcktsize"

        if plt["plt"] not in plot_types:
            errors = True
            print(c.INVAL_PLT % plt["plt"], file=sys.stderr)
        else:
            if plt["prot"] == "":
                errors = True
                print(c.NO_PROT % plt["prot"], file=sys.stderr)
            else:
                try:
                    plt["prot_snd"], plt["prot_rcv"] = plt["prot"].split(".")
                    plt["prot_snd"] += "-snd"
                    plt["prot_rcv"] += "-rcv"
                    del plt["prot"]
                except ValueError:
                    errors = True
                    print(c.INVAL_PROT % (plt["prot"], plt["plt"]), file=sys.stderr)

            if plt["ip_loc"] not in ip_loc_types:
                errors = True
                print(c.INVAL_LOC % (plt["ip_loc"], plt["plt"]), file=sys.stderr)
    
            if plt["ip_attr"] not in ip_attr_types:
                errors = True
                print(c.INVAL_ATTR % (plt["ip_attr"], plt["plt"]), file=sys.stderr)

    if errors:
        print_usage(1)
    #End error checking

    #Create output file if it doesn't exist
    if not os.path.isfile(args.out_file):
        DataPresentation.DomainExport.create_csv(args.out_file)

    #Create the groups to run analysis with processes
    raw_files = [ [] for _ in range(num_proc) ]

    index = 0
    # Split the pcap files into num_proc groups
    for root, dirs, files in os.walk(args.in_dir):
        for filename in files:
            if filename.endswith("pcap") and not filename.startswith("."):
                raw_files[index].append(root + "/" + filename)
                index += 1
                if index >= num_proc:
                    index = 0

    print("Analyzing input pcap files...\n")
    # run analysis with num_proc processes
    procs = []
    pid = 0
    for files in raw_files:
        p = Process(target=run, args=(pid, files))
        procs.append(p)
        p.start()
        pid += 1

    for p in procs:
        p.join()

    DataPresentation.DomainExport.sort_csv(args.out_file)

    print("\nDestintaion analysis finished.")


def run(pid, pcap_files):
    for f in pcap_files:
        perform_analysis(pid, f)


def perform_analysis(pid, pcap_file):
    if not pcap_file.endswith(".pcap"):
        print(c.WRONG_EXT % ("An input file", "pcap (.pcap)", pcap_file), file=sys.stderr)
        return

    if not os.path.isfile(pcap_file):
        print(c.INVAL % ("Input pcap", pcap_file, "file"), file=sys.stderr)
        return

    print("Proc %s: Processing pcap file \"%s\"..." % (pid, pcap_file))
    cap = pyshark.FileCapture(pcap_file, use_json = True)
    Utils.sysUsage("PCAP file loading")

    base_ts = 0
    try:
        if args.no_time_shift:
            cap[0]
        else:
            base_ts = float(cap[0].frame_info.time_epoch)
    except KeyError:
        print(c.NO_PCKT % pcap_file, file=sys.stderr)
        return

    node_id = Node.NodeId(args.mac_addr, args.ip_addr)
    node_stats = Node.NodeStats(node_id, base_ts, devices)

    print("Proc %s: Processing packets..." % pid)
    for packet in cap:
        node_stats.processPacket(packet)

    cap.close()

    Utils.sysUsage("Packets processed")

    print("Proc %s: Mapping IP to host..." % pid)
    ip_map = IP.IPMapping()
    ip_map.extractFromFile(pcap_file)
    ip_map.loadOrgMapping(IP_TO_ORG)
    ip_map.loadCountryMapping(IP_TO_COUNTRY)

    Utils.sysUsage("TShark hosts loaded")

    print("Proc %s: Generating CSV output..." % pid)
    de = DataPresentation.DomainExport(node_stats.stats.stats, ip_map, GEO_DB_CITY, GEO_DB_COUNTRY)
    de.loadDiffIPFor("eth") if args.find_diff else de.loadIPFor("eth")
    de.loadDomains(args.dev, args.lab, args.experiment, args.network, pcap_file, str(base_ts))
    de.exportDataRows(args.out_file)

    print("Proc %s: Analyzed data from \"%s\" successfully written to \"%s\""
          % (pid, pcap_file, args.out_file))

    Utils.sysUsage("Data exported")

    if len(plots) != 0:
        print("Proc %s: Generating plots..." % pid)
        pm = DataPresentation.PlotManager(node_stats.stats.stats, plots)
        pm.ipMap = ip_map
        pm.generatePlot(pcap_file, args.fig_dir, GEO_DB_CITY, GEO_DB_COUNTRY)

        Utils.sysUsage("Plots generated")


if __name__ == "__main__":
    main()

