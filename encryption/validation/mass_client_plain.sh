#!/bin/bash
DIR_TXT=synthetic

#### PLAIN TEXT TRAFFIC ###
echo "Have you started the socket server by python socket_server.py 12346"
read ans
while ! [ "$ans" = "y" ]
do
    echo "Have you started the socket server by python socket_server.py 12346"
    read ans
done


echo "Have you started capture pcap? (in a separate window, run tshark -i lo0 -w ${DIR_TXT}/plain.pcap)"
read ans
while ! [ "$ans" = "y" ]
do
    echo "Have you started capture pcap? (in a separate window, run tshark -i lo0 -w ${DIR_TXT}/plain.pcap)"
    read ans
done
#exit 0

for f in ${DIR_TXT}/f*.txt
do
    python etp_client.py $f 0
#    break
done

#### ENCRYPT traffic ####

