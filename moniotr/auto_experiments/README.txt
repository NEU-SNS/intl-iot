============================
Mon(IoT)r RUNNING CONTROLLED EXPERIMENTS
============================

The script allows to run controlled/automated experiments on IoT devices using the companion device (e.g., google home, alexa, an android device etc.).
As an example we consider the experiment of switching on the philips bulb through the android app and switching on the philips bulb through alexa device

1) Install the following Ubuntu dependences:  
apt-get install android-tools-adb  android-tools-fastboot
Once the installation has been finished you can check the ADB version by running the following command, $ adb version after connecting the android device via usb cable to the server where moniotr is running. Also allowing USB Debugging on the Android device is needed. 

2) For Android app controlled experiments, run the script as: 
./auto_app.sh $file_with experiment_details $experiments_folder
In the folder examples you find the $file_with experiment_details called dev_auto.
The first line is for the above experiment.

The $file_with experiment_details has to be populated with the details about the experiments you wish to run. 
Each line represents a controlled experiment as follow: 
$device_name (as in monitor/etc/device.txt);$experiment_name;$device_mac_address;$companion_device_mac_address;$companion_device_name;$package_name_of_Android app;$time_to_sleep_after_opening_the_app;$time_to_sleep_between_a_functionality_and_other;$coordinate_to_tap_for_activate_the_functionality_on_the_phone

The $coordinate_to_tap_for_activate_the_functionality_on_the_phone can be found manually the first time by activating the Pointer location option on the Developer options settings on the phone. 

3) For audio controlled experiments (e.g., googlemini, Alexa), run the script as: 
 ./auto_app.sh $file_with experiment_details $experiments_folder
In the folder examples you find the $file_with experiment_details called dev_auto.
The second line is for the above experiment.

The $file_with experiment_details has to be populated with the details about the experiments you wish to run. 
Each line represents a controlled experiment as follow: 
$device_name (as in monitor/etc/device.txt);$name_of_the_experiment;$device_mac_address;$companion_device_mac_address;$companion_device_name;$audio_for_controlling_the_device_in_text_format;$time_to_seelp_after_opening_the_app;$time_to_sleep_between_a_functionality_and_other.

4) Results (the pcap files of the experiments) will be separated on two files with the following format: 
- $experiments_folder/$device_name/$experiment_name/$date.pcap
- $experiments_folder/$device_name/$experiment_name/date.companion.$companion_device_name.pcap


