# Models for identifying device activity 
Section 6
 
Dependencies: pip3 install -r requirements.txt   
We need python3 to run the scripts. 

More explanations on ML models: [Model.md](Model.md)

Definition of the device activity: tag name 
[gdoc exp](https://docs.google.com/document/d/1_s6brtocKG0zpdTVNWOxZZdJ1WSkJKKw9gbZh_32WJU/edit)

Download [Google Drive > iot-model.tgz](https://drive.google.com/open?id=1lMqZ5qx6ATqIIiLOdTYcSm6RliK1F7vA) (size = ~127MB) before running the Juypter Notebook.

[model_sample.ipynb](model_sample.ipynb) walks you through steps that trains a model from traffic of experiments and uses the model to classify (predict) a new traffic observed.

`model.sh` is an equivalent to the Jupyter Notebook, which can be run directly in the terminal. To ananalyze the example data provided, run the following command:

```
./model.sh list_exp.txt tagged-intermediate/us/ features/us/ tagged-models/us/ yi-camera sample-yi-camera-recording.pcap sample-result.csv
```
