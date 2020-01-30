#!/bin/bash
DIR_TXT=synthetic

if [ ! -d "$DIR_TXT" ]
then
	echo "The ${DIR_TXT}/ directory does not exist."
	exit 0
fi

for f in ${DIR_TXT}/f*.txt
do
    ef=${f%.txt}.enc
    if ! [ -e $ef ]
    then
        python encrypt.py $f $ef
    fi
done
