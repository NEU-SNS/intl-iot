import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelBinarizer
from sklearn.metrics import accuracy_score

import warnings
warnings.simplefilter("ignore", category=DeprecationWarning)
root_feature = ''
root_model = ''
output_file = root_model + '/output/train-models.txt'

def usage():
    print("Usage: python %s in_features_dir out_model_dir\n" % os.path.basename(__file__))
    print("Trains analyzed pcap files and produces a model that can predict device activities.\n")
    print("Example: %s features/us/ tagged-models/us/\n" % os.path.basename(__file__))
    print("Arguments:")
    print("  in_features_dir: Path to a directory containing CSV files of statistically-analyzed pcap files")
    print("  out_model_dir: Path to the directory to put the generated model")

def main():
    test()
    global root_feature, root_model, output_file

    print("\nTraining data and creating model...")
    print("Running train_rf_models.py...")

    if len(sys.argv) != 3:
        print("\033[31mError: 2 Arguments required. %d arguments found.\033[39m" % (len(sys.argv) - 1))
        usage()
        return 0
    if not os.path.isdir(sys.argv[1]):
        print("\033[31mError: Input directory %s does not exist!\033[39m" % sys.argv[1])
        usage()
        return 0

    root_feature = sys.argv[1]
    root_model = sys.argv[2]
    output_file = root_model + '/output/train-models.txt'
    diroutput = root_model + '/output'
    if not os.path.exists(diroutput):
        os.system('mkdir -pv %s' % diroutput)
    train_models()

def train_models():
    global root_feature, root_model, output_file
    
    output = '' #Concatenation of device accuracy scores to be put in output_file

    #Each device has its own CSV file in the input directory
    for csv_file in os.listdir(root_feature):
        if csv_file.endswith('.csv'):
            train_data_file = '%s/%s' % (root_feature, csv_file)
            dname = csv_file[:-4]
            model_file = '%s/%s.model' % (root_model, csv_file[:-4])
            label_file = '%s/%s.label.txt' % (root_model, csv_file[:-4])
            res_file = model_file[:-6] + '_eval.txt'
            if os.path.exists(model_file) and os.path.exists(output_file) and os.path.exists(label_file):
                print('Output already produced for %s' % dname)
            elif not os.path.exists(train_data_file):
                print("Input file %s does not exist!" % train_data_file)
            else:
                print("Scanning " + train_data_file)
                _acc_score = train_individual_device(train_data_file, model_file, label_file, res_file)
                output = output + dname + '\t' + str(_acc_score) + '\n'
                ff = open(output_file, 'w')
                ff.write(output)
                ff.close()
    print('Accuracy scores saved to %s' % output_file)

def train_individual_device(train_data_file, model_file, label_file, res_file=None):
    # FutureWarning
    warnings.simplefilter("ignore", category=DeprecationWarning)
    warnings.simplefilter("ignore", category=FutureWarning)
    """
    Read from train_data_file of the features 
        meanBytes,minBytes,maxBytes,medAbsDev,skewLength,kurtosisLength,
        q10,q20,q30,q40,q50,q60,q70,q80,q90,spanOfGroup,meanTBP,varTBP,
        medianTBP,kurtosisTBP,skewTBP,device,state
    """
    train_data = pd.read_csv(train_data_file)
    if len(train_data) < 1:
        return
    print('  Data points: %d '%len(train_data))
    feature_data = train_data.drop(['device', 'state'], axis=1).fillna(-1)
    device = np.array(train_data.device)[0]
    y_labels = np.array(train_data.state)
    num_lables = len(set(y_labels))
    if num_lables < 2:
        return

    lb = LabelBinarizer()
    lb.fit(y_labels)

    onehot_encoded = lb.transform(y_labels)
    rf = RandomForestClassifier(n_estimators=1000, random_state=42)
    rf.fit(feature_data, onehot_encoded)
    y_pred = rf.predict(feature_data).round()
    res_acc = accuracy_score(onehot_encoded, y_pred)

    feature_list = list(feature_data.columns)
    importances = list(rf.feature_importances_)
    feature_importances = [(feature, round(importance, 3)) for feature, importance in zip(feature_list, importances)]
    feature_importances = sorted(feature_importances, key=lambda x: x[1], reverse=True)
    for pair in feature_importances:
        print('\tVariable: {:20} Importance: {}'.format(*pair))
    pickle.dump(rf, open(model_file, 'wb'))
    print('  Model -> %s' % (model_file))
    unique_labels = lb.classes_.tolist()
    open(label_file, 'w').write('%s\n' % '\n'.join(unique_labels))
    print('  Labels -> %s' % label_file)
    print ('  Accuracy: %s' % res_acc)
    return res_acc


def test():
    pc_name = os.uname()[1]
    """
    Test locally at JJ's Mac
    """
    if pc_name == 'JMac.local':
        train_individual_device('examples/amcrest-cam-wired.csv',
                                'examples/amcrest-cam-wired.model',
                                'examples/amcrest-cam-wired.label.txt')
        exit(0)


if __name__ == '__main__':
    main()
