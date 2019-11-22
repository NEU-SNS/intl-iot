#!/bin/bash
DIR_TXT=synthetic


for f in ${DIR_TXT}/f*.txt
do
    ef=${f%.txt}.enc
    if ! [ -e $ef ]
    then
        python encrypt.py $f $ef
    fi
done