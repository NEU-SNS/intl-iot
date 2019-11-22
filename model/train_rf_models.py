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
root_feature = 'features/us'
root_model='tagged-models/us'
output_file=root_model+'/output/train-models.txt'

def main():
    test()
    global root_feature, root_model, output_file
    if len(sys.argv) == 3:
        root_feature = sys.argv[1]
        root_model = sys.argv[2]
        output_file = root_model + '/output/train-models.txt'
    diroutput=root_model+'/output'
    if not os.path.exists(diroutput):
        os.system('mkdir -pv %s' % diroutput)
    train_models()


def train_models():
    global root_feature, root_model, output_file
    ff = open(output_file, 'a+')
    for csv_file in os.listdir(root_feature):
        if csv_file.endswith('.csv'):
            train_data_file = '%s/%s' % (root_feature, csv_file)
            print("Scanning " + train_data_file)
            dname = csv_file[:-4]
            model_file = '%s/%s.model' % (root_model, csv_file[:-4])
            label_file = '%s/%s.label.txt' % (root_model, csv_file[:-4])
            res_file = model_file[:-6] + '_eval.txt'
            if os.path.exists(model_file) or not os.path.exists(train_data_file):
                print('  Skip trained %s' % model_file)
                continue
            _acc_score = train_individual_device(train_data_file, model_file, label_file, res_file)
            ff.write('%s\t%s\n' % (dname, _acc_score))
    ff.close()
    print('acc score saved to %s' % output_file)

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
    print('  #Data points: %d '%len(train_data))
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
    print('  model -> %s' % (model_file))
    unique_labels = lb.classes_.tolist()
    open(label_file, 'w').write('%s\n' % '\n'.join(unique_labels))
    print('  labels -> %s' % label_file)
    print ('    accuracy: %s' % res_acc)
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