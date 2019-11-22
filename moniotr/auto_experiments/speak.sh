#!/bin/bash
say() { local IFS=+;/usr/bin/mplayer -ao alsa -really-quiet -noconsolecontrols "http://translate.google.com/translate_tts?ie=UTF-8&client=tw-ob&q=$*&tl=en"; }

IFS=':' read -r -a array <<< $*

NUM=${#array[@]}
for index in "${!array[@]}"
do
    [[ -n ${array[index]} ]] && say ${array[index]} &> /dev/null
    if (( index+1 < NUM )); then
        sleep 2
    fi
done
