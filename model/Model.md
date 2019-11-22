## ML models to detect device activity 

### Problem statement   
For a specified device, given a sequence of network frames, what is the device activity?

Examples:
- device:  amcrest-cam-wiredd
- network traffic: 10 minutes of network traffic
- device activity: one of 
    - movement
    - power
    - watch_android
    - watch_cloud_android
    - watch_cloud_ios
    - watch_ios
    
**++ Cases**: the 10' traffic could have more than one activity.     


### ML

During evaluation, we use following algorithms:
- rf:  [RandomForestClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html) (supervised)
- knn: [KNeighborsClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.KNeighborsClassifier.html) (supervised) 
- kmeans: [MiniBatchKMeans](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.MiniBatchKMeans.html) (unsupervised)
- dbscan: [DBSCAN](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.DBSCAN.html) (unsupervised)

For the purpose of IMC submission, we don't consider unsupervised approach (i.e. kmeans, dbscan).  


### Variables in sklearn:
N samples of M features of L classes
- X_features: features of N samples, N * M,  
- y_labels: labels of N samples
- X_train: default 70% of N samples (shuffled)
- X_test: default 30% of N samples (shuffled)
- y_train: original encoded values, e.g. "watch_ios_on"
    - y_train_bin: onehot encoded, e.g. [0, 1, 0, 0] as watch_ios_on is the second in the .classes_
- y_test: original encoded values
    - y_test_bin: onehot encoded
    - y_test_bin_1d: encoded values  
    - y_predicted: onehot encoded prediction of X_test
    - y_predicted_1d: encoded values
    - y_predicted_label: original values
- _acc_score: Trained with X_train,y_train; eval with X_test, y_test; refer to [accuracy_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.accuracy_score.html)
-  _complete: refer to [completeness_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.completeness_score.html#sklearn.metrics.completeness_score)
    > This metric is independent of the absolute values of the labels: a permutation of the class or cluster label values won’t change the score value in any way.
-  _silhouette: [silhouetee_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.silhouette_score.html#sklearn.metrics.silhouette_score)
    
