#!/bin/bash

#To retry the list of installed apps: adb shell "pm list packages -3"|cut -f 2 -d ":"
#To check the coordinate to tap: settings/Developer options/Pointer location

DATE=`date "+%Y%m%d_%H%M%S"`

# If running the script without parameters, dev_auto is used, and all experiments executed and tagged
# If running the script with parameters: $1 is the experiment file (default: 'dev_auto')
# $2 is the tag dir. If it is 'default' the experiment is tagged in the default directory, if 'notag' the experiment is not tagged (default: 'default') 
# $3 is the device to experiment with (if the option is not provided, all devices will be tested)
# $4 is the experiment to be started (if the option is not provided, all experiments for the chosen device will be started)
DEV_AUTO="$1"
TAG_DIR="$2"
DO_DEVICE="$3"
DO_EXPERIMENT="$4"
[ -z "$DEV_AUTO" ] && DEV_AUTO="dev_auto"
[ -z "$TAG_DIR" ] && TAG_DIR="default"

while IFS=";" read name name_exp mac phone phone_exp package sleep1 sleep2 function_1 function_2 function_3 function_4 function_5 function_6 function_7 function_8 function_9
do
    # Ignore commented lines starting with # (spaces before # are allowed)
    [[ $name  =~ ^[[:space:]]*# ]] && continue
    # Ignore empty lines and lines with only spaces
    [[ $name  =~ ^[[:space:]]*$ ]] && continue
    # Run only experiments matching the given device (if provided)
    [[ -n "$DO_DEVICE" ]] && [[ "$DO_DEVICE" != "$name" ]] && continue
    # Run only experiments matching the given experiment name (if provided)
    [[ -n "$DO_EXPERIMENT" ]] && [[ "$DO_EXPERIMENT" != "$name_exp" ]] && continue

    echo "Cancel past experiment $name_exp for device $name"
    [ "$TAG_DIR" != "notag" ] && /opt/moniotr/bin/tag-experiment cancel $name $name_exp
    echo "Starting experiment $name_exp for device $name"
    echo $DO_DEVICE $name $DO_EXPERIMENT $name_exp $phone_exp
    if [[ "$TAG_DIR" != "notag" ]] && [[ $phone_exp != "x" ]]; then
        /opt/moniotr/bin/tag-experiment start-with-companion $name $phone_exp $name_exp
    elif [[ "$TAG_DIR" != "notag" ]] && [[ $phone_exp == "x" ]]; then
        /opt/moniotr/bin/tag-experiment start $name $name_exp
    fi

    if [[ $phone_exp == *"echo"* || $phone_exp == *"google"* || $phone_exp == "allure-speaker" || $phone_exp == "x" ]]; then
        echo "echo..."
        sleep $sleep1
        ./speak.sh $package
	sleep $sleep2
    else
        #echo "Starting app for device" $name_dev
        adb shell -n monkey -p $package -c android.intent.category.LAUNCHER 1
        sleep $sleep1

        #scroll just in case and run functionalities
        #echo "Starting functionalities for device $name"
        [ -n "$function_1" ] && ( adb shell -n input $function_1 ; sleep 3s )
        [ -n "$function_2" ] && ( adb shell -n input $function_2 ; sleep 3s )
        [ -n "$function_3" ] && ( adb shell -n input $function_3 ; sleep 3s )
        [ -n "$function_4" ] && ( adb shell -n input $function_4 ; sleep 3s )
        [ -n "$function_5" ] && ( adb shell -n input $function_5 ; sleep 3s )
        [ -n "$function_6" ] && ( adb shell -n input $function_6 ; sleep 3s )
        [ -n "$function_7" ] && ( adb shell -n input $function_7 ; sleep 3s )
        [ -n "$function_8" ] && ( adb shell -n input $function_8 ; sleep 3s )
        [ -n "$function_9" ] && ( adb shell -n input $function_9 ; sleep 3s )
        sleep $sleep2
	echo "Stop experiment for device" $name_dev
        adb shell -n am force-stop $package
    fi

    sleep 5s
    if [ "$TAG_DIR" != "notag" ]; then
        if [ "$TAG_DIR" == "default" ]; then
            /opt/moniotr/bin/tag-experiment stop $name $name_exp
        else
            /opt/moniotr/bin/tag-experiment stop $name $name_exp $TAG_DIR
        fi
    fi
done < $DEV_AUTO
