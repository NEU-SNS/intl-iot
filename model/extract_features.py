import os
import sys
import time
import pandas as pd
import numpy as np
from scipy.stats import kurtosis
from scipy.stats import skew
from statsmodels import robust

columns_intermediate = ['frame_no', 'ts', 'ts_delta', 'protocols', 'frame_len', 'eth_src',
                        'eth_dst', 'ip_src', 'ip_dst', 'tcp_srcport', 'tcp_dstport',
                        'http_host', 'sni', 'udp_srcport', 'udp_dstport']

columns_state_features = ["start_time", "end_time", "meanBytes", "minBytes", "maxBytes",
                            "medAbsDev", "skewLength",
                          "kurtosisLength", "q10", "q20", "q30", "q40", "q50", "q60",
                          "q70", "q80", "q90", "spanOfGroup", "meanTBP", "varTBP",
                          "medianTBP", "kurtosisTBP", "skewTBP", "network_to", "network_from",
                          "network_both", "network_to_external", "network_local",
                          "anonymous_source_destination", "device", "state"]

# import warnings

"""
INPUT: intermediate files
OUTPUT: features for RFT models, with device and state labels 
"""

root_exp = ''
root_feature = ''

random_ratio=0.8
num_per_exp=10

RED = "\033[31;1m"
END = "\033[0m"

usage_stm = """
Usage: python3 {prog_name} in_imd_dir out_features_dir

Performs statistical analysis on decoded pcap files.

Example: python3 {prog_name} tagged-intermediate/us/ features/us/

Arguments:
  in_imd_dir:       path to a directory containing text files of decoded pcap data
  out_features_dir: path to the directory to write the analyzed CSV files;
                      directory will be generated if it does not already exist

For more information, see the README or model_details.md.""".format(prog_name=sys.argv[0])

#isError is either 0 or 1
def print_usage(isError):
    if isError == 0:
        print(usage_stm)
    else:
        print(usage_stm, file=sys.stderr)
    exit(isError)

def main():
    global root_exp, root_feature
    path = sys.argv[0]
    print("Running %s..." % path)

    for arg in sys.argv:
        if arg in ("-h", "--help"):
            print_usage(0)

    if len(sys.argv) != 3:
        print("%s%s: Error: 2 arguments required. %d arguments found.%s"
                % (RED, path, (len(sys.argv) - 1), END), file=sys.stderr)
        print_usage(1)

    if not os.path.isdir(sys.argv[1]):
        print("%s%s: Error: Input directory %s does not exist!%s"
                % (RED, path, sys.argv[1], END), file=sys.stderr)
        print_usage(1)

    root_exp = sys.argv[1]
    root_feature = sys.argv[2]
    print("Input files located in: %s" % root_exp)
    print("Output files placed in: %s" % root_feature)
    prepare_features()

def prepare_features():
    global root_exp, root_feature
    group_size = 50
    dict_intermediates = dict()
    dircache = root_feature + '/caches'
    if not os.path.exists(dircache):
        os.system('mkdir -pv %s' % dircache)
    #Parse input file names
    #root_exp/dir_device/dir_exp/intermeidate_file
    for dir_device in os.listdir(root_exp):
        training_file = root_feature + '/' + dir_device + '.csv' #Output file
        #Check if output file exists
        if os.path.exists(training_file):
            print('Features for %s prepared already in %s' % (dir_device, training_file))
            continue
        full_dir_device = root_exp + '/' + dir_device
        if os.path.isdir(full_dir_device) == False:
            continue
        for dir_exp in os.listdir(full_dir_device):
            full_dir_exp = full_dir_device + '/' + dir_exp
            if os.path.isdir(full_dir_exp) == False:
                continue
            for intermediate_file in os.listdir(full_dir_exp):
                full_intermediate_file = full_dir_exp + '/' + intermediate_file
                if intermediate_file[-4:] != ".txt":
                    print("%s is not a .txt file!" % full_intermediate_file)
                    continue
                if 'companion' in intermediate_file:
                    state = '%s_companion_%s' % (dir_exp, dir_device)
                    device = intermediate_file.split('.')[-2] # the word before pcap
                else:
                    state = dir_exp
                    device = dir_device
                feature_file = (root_feature + '/caches/' + device + '_' + state
                        + '_' + intermediate_file[:-4] + '.csv') #Output cache files
                paras = (full_intermediate_file, feature_file, group_size, device, state)
                #Dict contains devices that do not have an output file
                if device not in dict_intermediates:
                    dict_intermediates[device] = []
                dict_intermediates[device].append(paras)

    devices = "Feature files to be generated from following devices: "
    if len(dict_intermediates) == 0:
        devices = devices + "None"
    else:
        for key, value in dict_intermediates.items():
            devices = devices + key + ", "
        devices = devices[:-2]
    print(devices)

    for device in dict_intermediates:
        training_file = root_feature + '/' + device + '.csv'
        list_data= []
        list_paras = dict_intermediates[device]
        for paras in list_paras:
            full_intermediate_file = paras[0]
            feature_file = paras[1]
            group_size = paras[2]
            device = paras[3]
            state = paras[4]
            tmp_data = load_features_per_exp(
                    full_intermediate_file, feature_file, group_size, device, state)
            if tmp_data is None or len(tmp_data) == 0:
                continue
            list_data.append(tmp_data)
        if len(list_data) > 0:
            pd_device = pd.concat(list_data, ignore_index=True) #Concat all cache files together
            print('Saved to %s' % training_file)
            pd_device.to_csv(training_file, index=False) #Put in CSV file
    print('%s: Features prepared!' % time.time())

def load_features_per_exp(intermediate_file, feature_file, group_size, deviceName, state):
    #Load data from cache
    if os.path.exists(feature_file):
        print('    Load from %s' % feature_file)
        return pd.read_csv(feature_file)

    #Attempt to extract data from input files if not in previously-generated cache files
    feature_data = extract_features(intermediate_file, feature_file, group_size, deviceName, state)
    if feature_data is None or len(feature_data) == 0: #Can't extract from input files
        print('No data or features from %s' % intermediate_file)
        return
    else: #Cache was generated; save to file
        feature_data.to_csv(feature_file, index=False)
    return feature_data

#Create CSV cache file
def extract_features(intermediate_file, feature_file, group_size, deviceName, state):
    if not os.path.exists(intermediate_file):
        print('%s not exist' % intermediate_file)
        return
    col_names = columns_intermediate
    c= columns_state_features
    pd_obj_all = pd.read_csv(intermediate_file, names=col_names, sep='\t')
    pd_obj = pd_obj_all.loc[:, ['ts', 'ts_delta', 'frame_len','ip_src','ip_dst']]
    num_total = len(pd_obj_all)
    if pd_obj is None or num_total < 10:
        return
    print('Extracting from %s' % intermediate_file)
    print('   %s packets %s' % (num_total, feature_file))
    feature_data = pd.DataFrame()
    num_pkts = int(num_total * random_ratio)
    for di in range(0, num_per_exp):
        random_indices = list(np.random.choice(num_total, num_pkts))
        random_indices=sorted(random_indices)
        pd_obj = pd_obj_all.loc[random_indices, :]
        d = compute_tbp_features(pd_obj, deviceName, state)
        feature_data = feature_data.append(pd.DataFrame(data=[d], columns=c))
    return feature_data

#Use Pandas to perform stat analysis on raw data
def compute_tbp_features(pd_obj, deviceName, state):
    startTime = pd_obj.ts.iloc[0]
    endTime = pd_obj.ts.iloc[pd_obj.shape[0] - 1]
    meanBytes = pd_obj.frame_len.mean()
    minBytes = pd_obj.frame_len.min()
    maxBytes = pd_obj.frame_len.max()
    medAbsDev = robust.mad(pd_obj.frame_len)
    skewL = skew(pd_obj.frame_len)
    kurtL = kurtosis(pd_obj.frame_len)
    p = [10, 20, 30, 40, 50, 60, 70, 80, 90]
    percentiles = np.percentile(pd_obj.frame_len, p)
    spanG = pd_obj.ts.max() - pd_obj.ts.min()
    kurtT = kurtosis(pd_obj.ts_delta)
    skewT = skew(pd_obj.ts_delta)
    meanTBP = pd_obj.ts_delta.mean()
    varTBP = pd_obj.ts_delta.var()
    medTBP = pd_obj.ts_delta.median()
    network_to = 0 # Network going to 192.168.10.204, or home.
    network_from = 0 # Network going from 192.168.10.204, or home.
    network_both = 0 # Network going to/from 192.168.10.204, or home both present in source.
    network_local = 0
    network_to_external = 0 # Network not going to just 192.168.10.248.
    anonymous_source_destination = 0


    for i,j in zip(pd_obj.ip_src,pd_obj.ip_dst):
        if i == "192.168.10.204":
            network_from+=1
        elif j == "192.168.10.204":
            network_to+=1
        elif i == "192.168.10.248,192.168.10.204":
            network_both+=1
        elif j == "192.168.10.204,129.10.227.248":
            network_local+=1
        elif (j!="192.168.10.204" and i!="192.168.10.204"):
            network_to_external+=1
        else:
            anonymous_source_destination+=1



    d = [startTime, endTime, meanBytes, minBytes, maxBytes,
         medAbsDev, skewL, kurtL, percentiles[0],
         percentiles[1], percentiles[2], percentiles[3],
         percentiles[4], percentiles[5], percentiles[6],
         percentiles[7], percentiles[8], spanG, meanTBP, varTBP,
         medTBP, kurtT, skewT,network_to,network_from,
         network_both,network_to_external,network_local,anonymous_source_destination,
         deviceName, state]
    return d

if __name__ == '__main__':
    main()

