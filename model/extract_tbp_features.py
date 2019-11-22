import os
import sys
import time
import pandas as pd
import numpy as np
from scipy.stats import kurtosis
from scipy.stats import skew
from statsmodels import robust
columns_intermediate = ['frame_no','ts', 'ts_delta','protocols', 'frame_len', 'eth_src', 'eth_dst',
                        'ip_src', 'ip_dst', 'tcp_srcport', 'tcp_dstport', 'http_host', 'sni', 'udp_srcport', 'udp_dstport']

columns_state_features = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev", "skewLength", "kurtosisLength",
                           "q10", "q20", "q30", "q40", "q50", "q60", "q70", "q80", "q90", "spanOfGroup",
                           "meanTBP", "varTBP", "medianTBP", "kurtosisTBP", "skewTBP", "device", "state"]


# import warnings

"""
INPUT: intermediate files
OUTPUT: features for RFT models, with device and state labels 
"""

root_exp = 'tagged-intermediate/us'
root_feature = 'features/us'


random_ratio=0.8
num_per_exp=10

def main():
    global root_exp, root_feature
    print(root_exp)
    print(root_feature)
    if len(sys.argv) == 3:
        root_exp = sys.argv[1]
        root_feature = sys.argv[2]
    prepare_features()

def prepare_features():
    global root_exp, root_feature
    group_size = 50
    dict_intermediates = dict()
    dircache = root_feature + '/caches'
    if not os.path.exists(dircache): os.system('mkdir -pv %s' % dircache)
    for dir_device in os.listdir(root_exp):
        full_dir_device = root_exp + '/' + dir_device
        if os.path.isdir(full_dir_device) == False: continue
        for dir_exp in os.listdir(full_dir_device):
            full_dir_exp =  full_dir_device + '/' + dir_exp
            if os.path.isdir(full_dir_exp) == False: continue
            for intermediate_file in os.listdir(full_dir_exp):
                full_intermediate_file = full_dir_exp + '/' + intermediate_file
                if 'companion' in intermediate_file:
                    state = '%s_companion_%s' % (dir_exp, dir_device)
                    device = intermediate_file.split('.')[-2] # the word before pcap
                else:
                    state = dir_exp
                    device = dir_device
                training_file = root_feature + '/' + device + '.csv'
                if os.path.exists(training_file):
                    print('  Features for %s prepared already' % device)
                    continue
                feature_file = root_feature + '/caches/' + device + '_' + state + '_' + intermediate_file[:-4] + '.csv'
                paras = (full_intermediate_file, feature_file, group_size, device, state)
                if device not in dict_intermediates:
                    dict_intermediates[device] = []
                dict_intermediates[device].append(paras)
    print(dict_intermediates.keys())
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
            tmp_data = load_features_per_exp(full_intermediate_file, feature_file, group_size, device, state)
            if tmp_data is None or len(tmp_data) == 0:
                continue
            list_data.append(tmp_data)
        if len(list_data) > 0:
            pd_device = pd.concat(list_data, ignore_index=True)
            print('Saved to %s' % training_file)
            pd_device.to_csv(training_file, index=False)
    print('%s: Features prepared!' % time.time())

def load_features_per_exp(intermediate_file, feature_file, group_size, deviceName, state):
    if os.path.exists(feature_file):
        print('    Load from %s' % feature_file)
        return pd.read_csv(feature_file)

    feature_data = extract_features(intermediate_file, feature_file, group_size, deviceName, state)
    if feature_data is None or len(feature_data) == 0:
        print('No data or feature')
        return
    else:
        print('    Saved to %s' % feature_file)
        feature_data.to_csv(feature_file, index=False)
    return feature_data

def extract_features(intermediate_file, feature_file, group_size, deviceName, state):
    if not os.path.exists(intermediate_file):
        print('%s not exist' % intermediate_file)
        return
    col_names = columns_intermediate
    c= columns_state_features
    pd_obj_all = pd.read_csv(intermediate_file, names=col_names, sep='\t')
    pd_obj = pd_obj_all.loc[:, ['ts', 'ts_delta', 'frame_len']]
    num_total = len(pd_obj_all)
    if pd_obj is None or num_total < 10:
        return
    print('Total packets: %s' % num_total)
    feature_data = pd.DataFrame()
    num_pkts = int(num_total * random_ratio)
    for di in range(0, num_per_exp):
        random_indices = list(np.random.choice(num_total, num_pkts))
        random_indices=sorted(random_indices)
        pd_obj = pd_obj_all.loc[random_indices, :]
        d = compute_tbp_features(pd_obj, deviceName, state)
        feature_data = feature_data.append(pd.DataFrame(data=[d], columns=c))
    return feature_data

def compute_tbp_features(pd_obj, deviceName, state):
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

    d = [meanBytes, minBytes, maxBytes,
         medAbsDev, skewL, kurtL, percentiles[0],
         percentiles[1], percentiles[2], percentiles[3],
         percentiles[4], percentiles[5], percentiles[6],
         percentiles[7], percentiles[8], spanG, meanTBP, varTBP,
         medTBP, kurtT, skewT, deviceName, state]
    return d
#
# def test():
#     pc = os.uname()[1]
#     print(pc)
#     if pc == 'JMac.local':
#         feature_data=extract_features('../examples/example-unctrl.txt', '../examples/example-unctrl-tbp-features.csv', 10, 'somedevice', 'somestate')
#         print(feature_data)
#         exit(0)

if __name__ == '__main__':
    main()