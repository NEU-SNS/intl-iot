import sys
import pandas as pd
import numpy as np
import pickle
import time
import warnings
import ntpath
import os
from scipy.stats import kurtosis
from scipy.stats import skew
from statsmodels import robust
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

dir_online_features = 'online_features'
columns_intermediate = ['frame_no','ts', 'ts_delta','protocols', 'frame_len', 'eth_src', 'eth_dst',
                        'ip_src', 'ip_dst', 'tcp_srcport', 'tcp_dstport', 'http_host', 'sni', 'udp_srcport', 'udp_dstport']

columns_state_features = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev", "skewLength", "kurtosisLength",
                           "q10", "q20", "q30", "q40", "q50", "q60", "q70", "q80", "q90", "spanOfGroup",
                           "meanTBP", "varTBP", "medianTBP", "kurtosisTBP", "skewTBP","network_to","network_from",
                           "network_both","network_to_external","network_local","anonymous_source_destination","device", "state"]
columns_detect_sequence = ['ts', 'ts_end','ts_delta', 'num_pkt', 'state']
save_extracted_features = False

RED = "\033[31;1m"
END = "\033[0m"

usage_stm = """
Usage: python {prog_name} pcap_path model_dir device_name model_name result_path

Uses a model to predict the device activity given network traffic of that device.

Example: python {prog_name} yi_camera_sample.pcap tagged-models/us/ yi-camera rf sample.csv

Arguments:
  pcap_path:   path to the pcap file with unknown device activity
  model_dir:   path to the directory containing the directories of the models
  device_name: name of the model that generated the data in pcap_path
  model_name:  name of the model to be used to predict the device activity in pcap_path;
                 choose from kmeans, knn, or rf
  result_path: path to a CSV file to write results; will be generated if it does not
                 already exist

For more information, see model_details.md.""".format(prog_name=sys.argv[0])

def usage():
    print(usage_stm, file=sys.stderr)
    exit(1)

def main():
    global dir_models
    path = sys.argv[0]
    print("Running %s..." % path)

    if len(sys.argv) != 6:
        print("%s%s: Error: 5 arguments required. %d arguments found.%s" % (RED, path, (len(sys.argv) - 1), END), file=sys.stderr)
        usage()

    pcap_path = sys.argv[1]
    dir_models = sys.argv[2] + "/" + sys.argv[4]
    device = sys.argv[3]
    model_name = sys.argv[4]
    file_result = sys.argv[5]
    user_intermediates = "user-intermediates/"

    errors = False
    if not pcap_path.endswith('.pcap'):
        print("%s%s: Error: \"%s\" is not a pcap file.%s" % (RED, path, pcap_path, END), file=sys.stderr)
        errors = True
    elif not os.path.isfile(pcap_path):
        print("%s%s: Error: The pcap file \"%s\" does not exist.%s" % (RED, path, pcap_path, END), file=sys.stderr)
        errors = True

    if not file_result.endswith('.csv'):
        print("%s%s: Error: Output file \"%s\" is not a CSV file.%s" % (RED, path, file_result, END), file=sys.stderr)
        errors = True
    
    if not model_name in ("kmeans", "knn", "rf"):
        print("%s%s: Error: \"%s\" is not a valid model name. Choose from: kmeans, knn, or rf.%s" % (RED, path,  model_name, END), file=sys.stderr)
        errors = True
    elif not os.path.isdir(dir_models):
        print("%s%s: Error: The model directory %s does not exist!%s" % (RED, path, dir_models, END), file=sys.stderr)
        errors = True
    else:
        file_model = '%s/%s%s.model' % (dir_models, device, model_name)
        file_labels = '%s/%s.label.txt' % (dir_models, device)
        if not os.path.isfile(file_model):
            print("%s%s: Error: The model file %s cannot be found. Please regenerate file, check directory name, or check device name.%s" % (RED, path, file_model, END), file=sys.stderr)
            errors = True
        if not os.path.isfile(file_labels):
            print("%s%s: Error: The label file %s cannot be found. Please regenerate file, check directory name, or check device name.%s" % (RED, path, file_labels, END), file=sys.stderr)
            errors = True

    if errors:
        usage()

    print("Input pcap: %s" % pcap_path)
    print("Input model directory: %s" % dir_models)
    print("Device name: %s" % device)
    print("Model name: %s" % model_name)
    print("Output CSV: %s" % file_result)

    if not os.path.exists(user_intermediates):
        os.system('mkdir -pv %s' % user_intermediates)
    file_intermediate = user_intermediates + "/" + ntpath.basename(pcap_path)[:-4] + "txt"
    if os.path.isfile(file_intermediate):
        print("%s exists. Delete it to reparse the pcap file." % file_intermediate)
    else:
        os.system("tshark -r %s -Y ip -Tfields -e frame.number -e frame.time_epoch -e frame.time_delta -e frame.protocols -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e udp.srcport -e udp.dstport -E separator=/t > %s 2>/dev/null" % (pcap_path, file_intermediate))

    os.system('mkdir -pv `dirname %s`' % file_result)
    res = predict(device, file_intermediate)

    if res is None or len(res) == 0:
        with open(file_result, 'w') as ff:
            ff.write('No behavior found for %s from %s' % (device, file_intermediate))
    else:
        res['device'] = device
        res.to_csv(file_result, index=False)
    print('Results saved to %s' % file_result)


def predict(device, file_intermediate):
    model, labels = load_model(device)
    if model is None:
        return
    res_detect = detect_states(file_intermediate, model, labels, device)
    print('Results:')
    print(res_detect)
    return res_detect

def detect_states(intermediate_file, trained_model, labels, dname=None):
    group_size = 100
    warnings.simplefilter("ignore", category=DeprecationWarning)
    if not os.path.exists(intermediate_file):
        print('reading from %s' % intermediate_file)
        return
    feature_file = None
    ss = trained_model['standard_scaler']
    pca = trained_model['pca']
    trained_model = trained_model['trained_model']
    col_names = columns_intermediate
    c = columns_state_features.copy()
    col_data_points = ['ts', 'ts_end','ts_delta', 'num_pkt']
    c.extend(col_data_points)
    pd_obj_all = pd.read_csv(intermediate_file, names=col_names, sep='\t')
    pd_obj = pd_obj_all.loc[:, ['ts', 'ts_delta', 'frame_len','ip_src','ip_dst']]
    if pd_obj is None or len(pd_obj) < 1: #Nothing in decoded input pcap file
        return
    num_total = len(pd_obj_all)
    print('Total packets: %s' % num_total)
    feature_data = pd.DataFrame()
    list_start_ts_text = []
    """
    Slice into sessions     
    """
    list_sessions = list(pd_obj_all[pd_obj_all.ts_delta > 2].index)

    # todo: fix the bug that will return [] when there's no delta > 2
    if len(list_sessions) == 0:
        list_sessions.append(1)
        list_sessions.append(len(pd_obj_all))
    list_res = []
    min_ts = None
    """
    Load sessions, for each session, extract features and construct a dataframe of feature
    """
    print('Number of slices: %s' % len(list_sessions))
    for i in range(len(list_sessions) - 1):
        start = list_sessions[i]
        stop = list_sessions[i + 1]
        pd_obj = pd_obj_all.iloc[start: stop]
        if len(pd_obj) < group_size:
            # print('error: %s,%s' % (start, stop))
            # todo: aggregate to enlarge the session
            continue
        start_ts = pd_obj.iloc[0].ts
        if min_ts is None or start_ts < min_ts:
            min_ts = start_ts

        num_pkt = len(pd_obj)

        start_ts_delta = pd_obj.iloc[0].ts_delta
        list_start_ts_text.append('%s (%s) n=%s' % (start_ts, start_ts_delta, num_pkt))

        end_ts = pd_obj.iloc[num_pkt - 1].ts
        list_res.append([start_ts, end_ts, start_ts_delta, num_pkt]) #The results that are printed
        d = compute_tbp_features(pd_obj, np.NaN, np.NaN)
        d.extend([start_ts, end_ts, start_ts_delta, num_pkt])
        feature_data = feature_data.append(pd.DataFrame(data=[d], columns=c))

    """
    Predict 
    """
    if len(feature_data) == 0:
        print('  !<detect_states> No feature extracted from %s' % intermediate_file)
        return
    extra_cols = ['device', 'state']
    extra_cols.extend(col_data_points)

    # TODO : Make Model Pipeline more scalable from eval_models_all --> model_pipeline_example.ipynb
    unknown_data = feature_data.drop(extra_cols, axis=1)
    unknown_data = ss.transform(unknown_data)
    unknown_data = pca.transform(unknown_data)
    unknown_data = pd.DataFrame(unknown_data)
    unknown_data = unknown_data.iloc[:, :4]
    y_predict = trained_model.predict(unknown_data)
    p_readable = []
    theta = 0.7

    """
    Convert one hot encoding to labels, use a threshold to filter low confident predictions
    """
    # list_unknonw_indices = []
    # print_list(labels, 'labels: ')
    for pindex in range(len(y_predict)):
        y_max = np.max(y_predict[pindex])
        if y_max < theta:
            label_predicted = 'unknown'
            # list_unknonw_indices.append(pindex)
        else:
            label_predicted = labels[np.argmax(y_predict[pindex])]
        p_readable.append(label_predicted)

    """
    Save processed features & predictions to a csv for further classification 
    """
    # pd_unknown=feature_data[feature_data.index.isin(list_unknonw_indices)]
    # print_list(p_readable, 'readable:')
    # print(feature_data)
    feature_data['state'] = p_readable
    pd_unknown = feature_data
    pd_unknown.drop(['device', 'state'], axis=1)
    if save_extracted_features and len(pd_unknown) > 0 and dname is not None and min_ts is not None:
        pd_unknown['device'] = dname
        min_date = time.strftime("%Y-%m-%d-%s", time.localtime(min_ts))
        dir_online_features_device = '%s/%s' % (dir_online_features, dname)
        if not os.path.exists(dir_online_features_device):
            os.makedirs(dir_online_features_device, exist_ok=True)
        feature_file = '%s/%s.csv' % (dir_online_features_device, min_date)
        # pd_unknown = pd.concat(list_unknown, ignore_index=True)
        # print('Write unknown into %s' % feature_file)
        pd_unknown.to_csv(feature_file, index=False)

    """
    Save seqences of states into a .csv file
    """
    list_states = []
    for i in range(len(list_start_ts_text)):
        ts_text = list_start_ts_text[i]
        predicted = p_readable[i]
        entry = list_res[i]
        entry.append(predicted)
        list_states.append(entry)
        # print('%s: %s' % (ts_text, predicted))
    if len(list_states) > 0:
        return pd.DataFrame(list_states, columns=columns_detect_sequence)

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
    network_to = 0  # Network going to 192.168.10.204, or home.
    network_from = 0  # Network going from 192.168.10.204, or home.
    network_both = 0  # Network going to/from 192.168.10.204, or home both present in source.
    network_local = 0
    network_to_external = 0  # Network not going to just 192.168.10.248.
    anonymous_source_destination = 0

    for i, j in zip(pd_obj.ip_src, pd_obj.ip_dst):
        if i == "192.168.10.204":
            network_from += 1
        elif j == "192.168.10.204":
            network_to += 1
        elif i == "192.168.10.248,192.168.10.204":
            network_both += 1
        elif j == "192.168.10.204,129.10.227.248":
            network_local += 1
        elif (j != "192.168.10.204" and i != "192.168.10.204"):
            network_to_external += 1
        else:
            anonymous_source_destination += 1

    d = [meanBytes, minBytes, maxBytes,
         medAbsDev, skewL, kurtL, percentiles[0],
         percentiles[1], percentiles[2], percentiles[3],
         percentiles[4], percentiles[5], percentiles[6],
         percentiles[7], percentiles[8], spanG, meanTBP, varTBP,
         medTBP, kurtT, skewT, network_to, network_from,
         network_both, network_to_external, network_local, anonymous_source_destination,
         deviceName, state]
    return d

def load_model(dname):
    global dir_models
    for file in os.listdir(dir_models):
        if file.endswith(".model"):
            print(file)
            file_model = f'{dir_models}/{file}'
    file_labels = '%s/%s.label.txt' % (dir_models, dname)
    if os.path.exists(file_model) and os.path.exists(file_labels):
        print("Model: %s" % file_model)
        model = pickle.load(open(file_model, 'rb'))
        labels = load_list(file_labels)
        return model, labels
    else:
        print('No model for %s' % dname)
        return None, None

def load_list(fn, sym='#'):
    l = []
    if not os.path.exists(fn):
        # print '\tError: No such file %s'% fn
        return l
    with open(fn) as ff:
        for line in ff.readlines():
            line = line.strip()
            if line.startswith(sym) or line == '':
                continue
            l.append(line)
    return l

def print_list(l, prefix=''):
    print('%s %s' % (prefix, ','.join(l)))

if __name__ == '__main__':
    main()
